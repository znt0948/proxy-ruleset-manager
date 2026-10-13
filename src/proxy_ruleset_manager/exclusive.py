"""Make the published rule sets mutually exclusive across destinations.

Clients route with several rule sets (reject, download, direct).  sing-box
stops at the first matching rule, so overlapping sets silently depend on the
order of the client's route rules.  This step removes that dependency: after
it, a name or address is matched by the sets of at most one destination.

Conflicts are resolved by specificity, like longest-prefix routing:

* An entry that is more specific than the entry of another destination
  matching it (an exact domain under a suffix, a longer suffix under a
  shorter one, any domain under a keyword or regex, a longer IP prefix
  inside a shorter one) is carved out of that other set: its plain rules are
  wrapped in ``logical and`` with an inverted rule listing the exceptions.
  Entries of that set that are even more specific than an exception stay
  matched through an extra plain rule.
* Identical entries (same exact domain, same suffix, same CIDR) stay in one
  destination only: the one whose hand-kept self-host list holds the entry,
  otherwise the first destination in ``GROUPS`` order (the order clients
  evaluate today, so the result does not change behavior).

* Blocking is not overridden by routing preferences: a direct or download
  entry covered by a block list leaves its set (or excludes the blocking
  regex) even when it is more specific, since a direct list is not an
  allowlist. Exceptions: entries hand-kept in a self-host list, and blocks
  that come from a keyword (too broad to win; dnsapi.cn is no HTTPDNS).

Keyword-against-keyword and regex-against-regex overlaps cannot be decided
statically and are only reported.  Logical rules (from upstream, or from
AdGuard allow rules) are indexed through their positive parts and carved by
appending to their "and".  Passes repeat until verification finds no
overlap; the result is stable when run again.
"""

import ipaddress
import json
import logging
import os
import re

# Destinations in today's client evaluation order, with their published
# rule sets and the hand-kept self-host files feeding them.
GROUPS = (
    {
        "name": "reject",
        "files": (
            "geosite-blocker-trash@mobile.json",
            "geosite-blocker-httpdns.json",
            "geoip-blocker-httpdns.json",
            "adguard-blocker@mobile.json",
        ),
        "self_host": (),
    },
    {
        "name": "download",
        "files": (
            "geosite-category-download@!cn.json",
            "geosite-filter-downloadKeywords@!cn.json",
            "geoip-category-download@!cn.json",
        ),
        "self_host": (
            "self-host/geosite-download@selfhost.json",
            "self-host/geosite-download-keywords@selfhost.json",
            "self-host/geoip-download@selfhost.json",
        ),
    },
    {
        "name": "direct",
        "files": (
            "geosite-category-direct@light.json",
            "geoip-category-direct@light.json",
        ),
        "self_host": ("self-host/geosite-direct@selfhost.json",),
    },
)

LOGICAL_KEYS = {"type", "mode", "rules"}

# Specificity ranks.
EXACT, SUFFIX, PATTERN = 3, 2, 1


def _norm(name):
    return name.strip().lower().lstrip(".")


def _plain_rules(rules):
    return [rule for rule in rules if isinstance(rule, dict) and not LOGICAL_KEYS.issubset(rule) and not rule.get("invert")]


def _values(rule, field):
    values = rule.get(field, [])
    if isinstance(values, str):
        return [values]
    return [value for value in values if isinstance(value, str)]


class RuleIndex:
    """Matching index over the plain rules of one rule set."""

    def __init__(self, rules):
        self.domains, self.suffixes = set(), set()
        self.keywords, self.regexes = [], []
        self.networks = set()
        self._prefixes = None
        for rule in _flatten(rules):
            self.domains.update(_norm(v) for v in _values(rule, "domain"))
            self.suffixes.update(_norm(v) for v in _values(rule, "domain_suffix"))
            self.keywords.extend(v.lower() for v in _values(rule, "domain_keyword") if v)
            for pattern in _values(rule, "domain_regex"):
                try:
                    self.regexes.append((pattern, re.compile(pattern)))
                except re.error:
                    logging.warning("exclusive: skipping invalid regex %s", pattern)
            for value in _values(rule, "ip_cidr"):
                try:
                    self.networks.add(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    pass

    def entries(self):
        for name in self.domains:
            yield ("domain", name)
        for name in self.suffixes:
            yield ("domain_suffix", name)

    def match(self, name):
        """The most specific entry matching name: (rank, length, field, value)."""
        if name in self.domains:
            return (EXACT, len(name), "domain", name)
        candidate = name
        while candidate:
            if candidate in self.suffixes:
                return (SUFFIX, len(candidate), "domain_suffix", candidate)
            if "." not in candidate:
                break
            candidate = candidate.split(".", 1)[1]
        for keyword in self.keywords:
            if keyword in name:
                return (PATTERN, 0, "domain_keyword", keyword)
        for pattern, compiled in self.regexes:
            if compiled.search(name):
                return (PATTERN, 0, "domain_regex", pattern)
        return None

    def match_network(self, network):
        """The longest network of the index containing network (or None)."""
        if self._prefixes is None:
            self._prefixes = {(n.version, int(n.network_address), n.prefixlen): n for n in self.networks}
            self._lengths = {v: sorted({n.prefixlen for n in self.networks if n.version == v}, reverse=True) for v in (4, 6)}
        bits = network.max_prefixlen
        address = int(network.network_address)
        for prefix in self._lengths[network.version]:
            if prefix > network.prefixlen:
                continue
            key = (network.version, address >> (bits - prefix) << (bits - prefix), prefix)
            if key in self._prefixes:
                return self._prefixes[key]
        return None


def _entry_rank(field, value):
    return (EXACT if field == "domain" else SUFFIX, len(value))


def _self_host_entries(root):
    """Hand-kept entries by destination: {(field, value): destination}."""
    owners = {}
    for group in GROUPS:
        for path in group["self_host"]:
            full = os.path.join(root, path)
            if not os.path.exists(full) or not path.endswith(".json"):
                continue
            with open(full, encoding="utf-8") as file:
                rules = json.load(file).get("rules", [])
            for rule in _plain_rules(rules):
                for field in ("domain", "domain_suffix"):
                    for value in _values(rule, field):
                        owners.setdefault((field, _norm(value)), set()).add(group["name"])
                for value in _values(rule, "ip_cidr"):
                    try:
                        owners.setdefault(("ip_cidr", str(ipaddress.ip_network(value, strict=False))), set()).add(group["name"])
                    except ValueError:
                        pass
    return owners


MAX_PASSES = 4


def make_exclusive(output_directory, root=".", report_file=None):
    """Rewrite the rule sets in output_directory so destinations do not
    overlap; returns the report (also written to report_file if given).

    A pass can expose new overlaps (dropping a tied entry from one set lets a
    broader entry of that set match the name), so passes repeat until the
    verification finds none."""
    report = None
    for number in range(1, MAX_PASSES + 1):
        current = _exclusive_pass(output_directory, root)
        if report is None:
            report = current
        else:
            for key in ("ties", "carved", "blocked", "unresolved", "hand_conflicts"):
                report[key].extend(x for x in current[key] if x not in report[key])
            for filename, counts in current["summary"].items():
                total = report["summary"].setdefault(filename, {"removed": 0, "carved": 0})
                total["removed"] += counts["removed"]
                total["carved"] += counts["carved"]
        report["remaining"] = verify_exclusive(output_directory)
        report["passes"] = number
        if not report["remaining"] or not (current["ties"] or current["carved"] or current["blocked"]):
            break
    for conflict in report["hand_conflicts"]:
        logging.warning("exclusive: %s %s is hand-kept in %s; kept in %s",
                        conflict["field"], conflict["value"], ", ".join(conflict["destinations"]), conflict["destinations"][0])
    if report_file:
        os.makedirs(os.path.dirname(report_file) or ".", exist_ok=True)
        with open(report_file, "w", encoding="utf-8") as file:
            json.dump(report, file, ensure_ascii=False, indent=2)
            file.write("\n")
    return report


def _exclusive_pass(output_directory, root):
    sets = {}
    for group in GROUPS:
        for filename in group["files"]:
            path = os.path.join(output_directory, filename)
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as file:
                document = json.load(file)
            sets[filename] = {"group": group["name"], "path": path, "document": document,
                              "index": RuleIndex(document.get("rules", []))}
    order = [group["name"] for group in GROUPS]
    owners = _self_host_entries(root)

    removals = {filename: set() for filename in sets}    # (field, value) dropped
    exceptions = {filename: set() for filename in sets}  # (field, value) carved out
    report = {"ties": [], "carved": [], "blocked": [], "unresolved": [], "hand_conflicts": []}

    def winner(field, value, groups):
        hand = owners.get((field, value), set()) & set(groups)
        if len(hand) > 1:
            report["hand_conflicts"].append({"field": field, "value": value, "destinations": sorted(hand, key=order.index)})
        if hand:
            return min(hand, key=order.index)
        return min(groups, key=order.index)

    # Domain entries.
    for filename, info in sets.items():
        for field, value in info["index"].entries():
            rank = _entry_rank(field, value)
            for other, other_info in sets.items():
                if other_info["group"] == info["group"]:
                    continue
                matched = other_info["index"].match(value)
                if not matched:
                    continue
                other_rank = matched[:2]
                if other_rank == rank and matched[3] == value:
                    # Identical entry: decided once, from the winner's side.
                    keep = winner(field, value, [info["group"], other_info["group"]])
                    if keep == info["group"] and (field, value) not in removals[other]:
                        removals[other].add((field, value))
                        report["ties"].append({"field": field, "value": value, "kept_in": filename, "removed_from": other})
                elif (other_info["group"] == "reject" and info["group"] != "reject" and matched[2] != "domain_keyword"
                      and info["group"] not in owners.get((field, value), set())):
                    # Blocking wins over routing preferences: a direct or
                    # download entry the block list covers leaves its set
                    # (or, under a block regex, excludes that regex), unless
                    # it is hand-kept. Keyword blocks are too broad to win.
                    if matched[2] in ("domain", "domain_suffix"):
                        if (field, value) not in removals[filename]:
                            removals[filename].add((field, value))
                            report["blocked"].append({"field": field, "value": value, "removed_from": filename,
                                                      "blocked_by": other, "covering": {matched[2]: matched[3]}})
                    elif ("domain_regex", matched[3]) not in exceptions[filename]:
                        exceptions[filename].add(("domain_regex", matched[3]))
                        report["blocked"].append({"field": "domain_regex", "value": matched[3], "carved_from": filename,
                                                  "blocked_by": other, "covering": {field: value}})
                elif rank > other_rank:
                    if (field, value) not in exceptions[other]:
                        exceptions[other].add((field, value))
                        report["carved"].append({"field": field, "value": value, "kept_in": filename,
                                                 "carved_from": other, "covering": {matched[2]: matched[3]}})
                elif rank[0] == PATTERN and other_rank[0] == PATTERN:
                    report["unresolved"].append({"value": value, "sets": [filename, other]})

    # IP prefixes.
    for filename, info in sets.items():
        for network in info["index"].networks:
            for other, other_info in sets.items():
                if other_info["group"] == info["group"]:
                    continue
                container = other_info["index"].match_network(network)
                if container is None:
                    continue
                value = str(network)
                if container != network and other_info["group"] == "reject" and info["group"] != "reject" \
                        and info["group"] not in owners.get(("ip_cidr", value), set()):
                    if ("ip_cidr", value) not in removals[filename]:
                        removals[filename].add(("ip_cidr", value))
                        report["blocked"].append({"field": "ip_cidr", "value": value, "removed_from": filename,
                                                  "blocked_by": other, "covering": {"ip_cidr": str(container)}})
                    continue
                if container == network:
                    keep = winner("ip_cidr", value, [info["group"], other_info["group"]])
                    if keep == info["group"] and ("ip_cidr", value) not in removals[other]:
                        removals[other].add(("ip_cidr", value))
                        report["ties"].append({"field": "ip_cidr", "value": value, "kept_in": filename, "removed_from": other})
                elif ("ip_cidr", value) not in exceptions[other]:
                    exceptions[other].add(("ip_cidr", value))
                    report["carved"].append({"field": "ip_cidr", "value": value, "kept_in": filename,
                                             "carved_from": other, "covering": {"ip_cidr": str(container)}})

    for filename, info in sets.items():
        if not removals[filename] and not exceptions[filename]:
            continue
        info["document"]["rules"] = _rewrite(info["document"].get("rules", []), removals[filename], exceptions[filename])
        with open(info["path"], "w", encoding="utf-8") as file:
            json.dump(info["document"], file, ensure_ascii=False, indent=4)
            file.write("\n")

    for key in report:
        report[key].sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    report["summary"] = {
        filename: {"removed": len(removals[filename]), "carved": len(exceptions[filename])}
        for filename in sorted(sets) if removals[filename] or exceptions[filename]
    }
    return report


def _covered_by(field, value, exceptions):
    """Whether an exception covers the entry less specifically than itself
    (so the entry must stay matched explicitly)."""
    if field == "ip_cidr":
        network = ipaddress.ip_network(value, strict=False)
        for kind, exception in exceptions:
            if kind == "ip_cidr":
                carved = ipaddress.ip_network(exception, strict=False)
                if carved.version == network.version and network != carved and network.subnet_of(carved):
                    return True
        return False
    for kind, exception in exceptions:
        if kind == "domain_suffix" and value != exception and value.endswith("." + exception):
            return True
    return False


def _key(field, raw):
    return str(ipaddress.ip_network(raw, strict=False)) if field == "ip_cidr" else _norm(raw)


def _strip(rule, removals, pinned, exceptions):
    """Drop removed entries from a rule (recursing into the positive parts of
    logical rules) and move entries that must stay matched despite an
    exception into pinned. Returns None when nothing is left."""
    if LOGICAL_KEYS.issubset(rule):
        rule = dict(rule)
        subs = []
        for sub in rule["rules"]:
            if sub.get("invert"):
                subs.append(sub)
                continue
            sub = _strip(sub, removals, pinned, exceptions)
            if sub is not None:
                subs.append(sub)
        if not any(not sub.get("invert") for sub in subs):
            return None
        rule["rules"] = subs
        return rule
    rule = dict(rule)
    for field in ("domain", "domain_suffix", "ip_cidr"):
        if field not in rule:
            continue
        kept = []
        for raw in _values(rule, field):
            key = _key(field, raw)
            if (field, key) in removals:
                continue
            if exceptions and _covered_by(field, key, exceptions):
                pinned.setdefault(field, set()).add(raw)
                continue
            kept.append(raw)
        if kept:
            rule[field] = kept
        else:
            del rule[field]
    return rule if any(key != "invert" for key in rule) else None


def _inverted(exceptions):
    """One inverted rule per field family: sing-box ORs the domain fields of
    a rule but ANDs them with ip_cidr."""
    domain_excluded, ip_excluded = {}, {}
    for field, value in sorted(exceptions):
        (ip_excluded if field == "ip_cidr" else domain_excluded).setdefault(field, []).append(value)
    return [{**excluded, "invert": True} for excluded in (domain_excluded, ip_excluded) if excluded]


def _carve(rule, inverted):
    """rule AND NOT each inverted rule; appended to an existing "and" (merged
    with an inverted rule of the same family) instead of nesting."""
    if not inverted:
        return rule
    if not (LOGICAL_KEYS.issubset(rule) and rule.get("mode", "and") == "and" and not rule.get("invert")):
        return {"type": "logical", "mode": "and", "rules": [rule, *inverted]}
    subs = [dict(sub) for sub in rule["rules"]]
    for addition in inverted:
        family = "ip" if "ip_cidr" in addition else "domain"
        for sub in subs:
            if sub.get("invert") and not LOGICAL_KEYS.issubset(sub) and ("ip" if "ip_cidr" in sub else "domain") == family \
                    and all(k in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "invert") for k in sub):
                for field, values in addition.items():
                    if field != "invert":
                        sub[field] = sorted(set(_values(sub, field)) | set(values))
                break
        else:
            subs.append(addition)
    return {**rule, "rules": subs}


def _rewrite(rules, removals, exceptions):
    pinned, result = {}, []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("invert"):
            result.append(rule)
            continue
        stripped = _strip(rule, removals, pinned, exceptions)
        if stripped is not None:
            result.append(_carve(stripped, _inverted(exceptions)))
    if pinned:
        # Pinned entries are more specific than some exceptions; the others
        # (more specific than them) still apply.
        under = {(field, value) for field, value in exceptions
                 if any(_covered_by(f, _key(f, raw), {(field, value)}) for f, raws in pinned.items() for raw in raws)}
        rule = {field: sorted(values) for field, values in pinned.items()}
        result.append(_carve(rule, _inverted(exceptions - under)))
    return result


def _rule_matches(rule, name=None, address=None, cache=None):
    """sing-box headless rule semantics for a domain name or an address."""
    if cache is None:
        cache = {}
    if LOGICAL_KEYS.issubset(rule):
        results = [_rule_matches(sub, name, address, cache) for sub in rule["rules"]]
        result = all(results) if rule.get("mode", "and") == "and" else any(results)
    else:
        families = []
        domain_fields = [f for f in ("domain", "domain_suffix", "domain_keyword", "domain_regex") if f in rule]
        if domain_fields:
            matched = False
            if name is not None:
                index = cache.get(id(rule))
                if index is None:
                    index = cache[id(rule)] = RuleIndex([{f: rule[f] for f in domain_fields}])
                matched = index.match(name) is not None
            families.append(matched)
        if "ip_cidr" in rule:
            matched = False
            if address is not None:
                index = cache.get(("ip", id(rule)))
                if index is None:
                    index = cache[("ip", id(rule))] = RuleIndex([{"ip_cidr": rule["ip_cidr"]}])
                matched = index.match_network(ipaddress.ip_network(address)) is not None
            families.append(matched)
        result = bool(families) and all(families)
    return result != bool(rule.get("invert"))


def verify_exclusive(output_directory):
    """Names and addresses of the rule sets still matched by more than one
    destination, evaluated with the rewritten rules."""
    documents = []
    for group in GROUPS:
        for filename in group["files"]:
            path = os.path.join(output_directory, filename)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as file:
                    documents.append((group["name"], filename, json.load(file).get("rules", [])))
    probes = set()
    for _, _, rules in documents:
        index = RuleIndex(_flatten(rules))
        probes.update(("name", value) for _, value in index.entries())
        probes.update(("address", network.network_address) for network in index.networks)
    remaining, cache = [], {}
    for kind, probe in sorted(probes, key=str):
        groups = {}
        for group, filename, rules in documents:
            arguments = {"name": probe} if kind == "name" else {"address": probe}
            if any(_rule_matches(rule, cache=cache, **arguments) for rule in rules if isinstance(rule, dict)):
                groups.setdefault(group, []).append(filename)
        if len(groups) > 1:
            remaining.append({"probe": str(probe), "matched_by": groups})
    return remaining


def _flatten(rules):
    """Plain positive rules, including those inside logical wrappers."""
    flat = []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("invert"):
            continue
        if LOGICAL_KEYS.issubset(rule):
            flat.extend(_flatten(rule["rules"]))
        else:
            flat.append(rule)
    return flat
