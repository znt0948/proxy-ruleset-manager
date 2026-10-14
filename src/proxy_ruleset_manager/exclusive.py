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

import functools
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

# The order clients evaluate the domain rule sets today (route rules; the
# keyword set comes after direct), used to report what changes.
CLIENT_ORDER = (
    ("reject", "geosite-blocker-trash@mobile.json"),
    ("reject", "geosite-blocker-httpdns.json"),
    ("reject", "adguard-blocker@mobile.json"),
    ("download", "geosite-category-download@!cn.json"),
    ("direct", "geosite-category-direct@light.json"),
    ("download", "geosite-filter-downloadKeywords@!cn.json"),
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


@functools.lru_cache(maxsize=None)
def _regex_tails(pattern):
    """Literal endings a regex's matches must have: a set of strings,
    "nodot" when it cannot match a dotted name, or None when unknown."""
    if "." not in pattern and not any(x in pattern for x in ("\\S", "\\W", "\\D", "[^")):
        return "nodot"
    if not pattern.endswith("$") or pattern.endswith("\\$"):
        return None
    body, tail = pattern[:-1], ""
    while body:
        if body.endswith("\\.") and not body.endswith("\\\\."):
            tail, body = "." + tail, body[:-2]
        elif re.fullmatch(r"[a-z0-9_-]", body[-1]) and not body[:-1].endswith("\\"):
            tail, body = body[-1] + tail, body[:-1]
        else:
            break
    if body.endswith(")") and "(" in body:
        group = body[body.rindex("(") + 1:-1].removeprefix("?:")
        alternatives = group.split("|")
        if all(re.fullmatch(r"(?:[a-z0-9_-]|\\\.)+", alt) for alt in alternatives):
            return {alt.replace("\\.", ".") + tail for alt in alternatives}
    return {tail} if tail.strip(".") else None


def _intersects(pattern_field, pattern, compiled, field, value):
    """Whether a keyword or regex can match a name the entry matches (the
    name itself, or any name under a suffix). Errs towards True."""
    if pattern_field == "domain_keyword":
        return pattern in value if field == "domain" else True
    if compiled is not None and compiled.search(value):
        return True
    if field == "domain":
        return False
    tails = _regex_tails(pattern)
    if tails is None:
        return True
    if tails == "nodot":
        return False
    for tail in tails:
        literal = tail.lstrip(".")
        if literal == value or literal.endswith("." + value) or value.endswith(literal):
            return True
    return False


def _patterns_intersect(field_a, a, field_b, b):
    """Whether two patterns may match a common name. Errs towards True."""
    tails = [_regex_tails(p) if f == "domain_regex" else None for f, p in ((field_a, a), (field_b, b))]
    if "nodot" in tails:
        other = (field_b, b) if tails[0] == "nodot" else (field_a, a)
        return not (other[0] == "domain_keyword" and "." in other[1]) and _regex_tails(other[1]) != {""}
    if isinstance(tails[0], set) and isinstance(tails[1], set):
        return any(x.endswith(y) or y.endswith(x) for x in tails[0] for y in tails[1])
    return True


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


def make_exclusive(output_directory, root=".", report_file=None, pre_directory=None):
    """Rewrite the rule sets in output_directory so destinations do not
    overlap; returns the report (also written to report_file if given).
    With pre_directory, the rule sets as they were before are copied there
    first (for the real sing-box differential test).

    A pass can expose new overlaps (dropping a tied entry from one set lets a
    broader entry of that set match the name), so passes repeat until the
    verification finds none."""
    before = _load_documents(output_directory)
    if pre_directory:
        os.makedirs(pre_directory, exist_ok=True)
        for _, filename, rules in before:
            with open(os.path.join(pre_directory, filename), "w", encoding="utf-8") as file:
                json.dump({"version": 3, "rules": rules}, file, ensure_ascii=False)
    report = None
    for number in range(1, MAX_PASSES + 1):
        current = _exclusive_pass(output_directory, root)
        if report is None:
            report = current
        else:
            for key in ("ties", "carved", "blocked", "regions", "unresolved", "hand_conflicts"):
                report[key].extend(x for x in current[key] if x not in report[key])
            for filename, counts in current["summary"].items():
                total = report["summary"].setdefault(filename, {"removed": 0, "carved": 0})
                total["removed"] += counts["removed"]
                total["carved"] += counts["carved"]
        report["remaining"] = verify_exclusive(output_directory)
        report["passes"] = number
        if not report["remaining"] or not any(current[key] for key in ("ties", "carved", "blocked", "regions")):
            break
    report["changed"], report["orphaned"] = _compare(before, _load_documents(output_directory), _probes(before))
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
    report = {"ties": [], "carved": [], "blocked": [], "regions": [], "unresolved": [], "hand_conflicts": []}

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
                    if matched[2] in ("domain", "domain_suffix") or field == "domain":
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

    # Pattern regions: a keyword or regex can overlap the subtree of another
    # destination's suffix without equaling any listed name.
    for filename, info in sets.items():
        index = info["index"]
        patterns = [("domain_keyword", k, None) for k in index.keywords] + [("domain_regex", p, c) for p, c in index.regexes]
        for pattern_field, pattern, compiled in patterns:
            for other, other_info in sets.items():
                if other_info["group"] == info["group"]:
                    continue
                # Entries the other set gives up (removed, or carved out of it)
                # cannot take a region over: carving them would leave names
                # without any match.
                hits = [(f, v) for f, v in other_info["index"].entries()
                        if (f, v) not in removals[other] and (f, v) not in exceptions[other]
                        and _intersects(pattern_field, pattern, compiled, f, v)]
                # Patterns of the other destination that may overlap this one.
                other_index = other_info["index"]
                other_patterns = [("domain_keyword", k) for k in other_index.keywords] + [("domain_regex", p) for p, _ in other_index.regexes]
                for other_field, other_pattern in other_patterns:
                    if not _patterns_intersect(pattern_field, pattern, other_field, other_pattern):
                        continue
                    # Blocking beats routing; between routing patterns direct
                    # beats download (the keyword set is evaluated after the
                    # direct one by clients today).
                    rank_of = {"reject": 0, "direct": 1, "download": 2}
                    if rank_of[info["group"]] < rank_of[other_info["group"]]:
                        if (pattern_field, pattern) not in exceptions[other]:
                            exceptions[other].add((pattern_field, pattern))
                            report["regions"].append({"pattern": {pattern_field: pattern}, "kept_in": filename,
                                                      "excluded_from": other, "overlapping_pattern": {other_field: other_pattern}})
                if not hits:
                    continue
                if info["group"] == "reject" and other_info["group"] != "reject":
                    # Blocking wins in the region; listed names the pattern
                    # itself hits and that won above stay pinned.
                    if (pattern_field, pattern) not in exceptions[other]:
                        exceptions[other].add((pattern_field, pattern))
                        report["regions"].append({"pattern": {pattern_field: pattern}, "kept_in": filename,
                                                  "excluded_from": other, "overlapping_entries": len(hits)})
                else:
                    # Explicit entries win over a pattern of another destination.
                    added = [hit for hit in hits if hit not in exceptions[filename]]
                    exceptions[filename].update(added)
                    if added:
                        report["regions"].append({"pattern": {pattern_field: pattern}, "carved_from": filename,
                                                  "entries_of": other, "carved_entries": len(added)})

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
        protected = {(c["field"], c["value"]) for c in report["carved"] if c["kept_in"] == filename}
        info["document"]["rules"] = _rewrite(info["document"].get("rules", []), removals[filename], exceptions[filename], protected)
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
        if kind == "domain_keyword" and exception in value:
            return True
        if kind == "domain_regex":
            try:
                if re.search(exception, value):
                    return True
            except re.error:
                pass
    return False


def _key(field, raw):
    return str(ipaddress.ip_network(raw, strict=False)) if field == "ip_cidr" else _norm(raw)


def _strip(rule, removals, pinned, exceptions, protected):
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
            sub = _strip(sub, removals, pinned, exceptions, protected)
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
            if (field, key) in protected and exceptions and _covered_by(field, key, exceptions):
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


def _rewrite(rules, removals, exceptions, protected=frozenset()):
    pinned, result = {}, []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("invert"):
            result.append(rule)
            continue
        stripped = _strip(rule, removals, pinned, exceptions, protected)
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


def _load_documents(output_directory):
    documents = []
    for group in GROUPS:
        for filename in group["files"]:
            path = os.path.join(output_directory, filename)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as file:
                    documents.append((group["name"], filename, json.load(file).get("rules", [])))
    return documents


def _destination(documents, name, cache):
    """The destination a client picks for name: the first matching domain
    set in client order (None when no set matches)."""
    by_file = {filename: (group, rules) for group, filename, rules in documents}
    for group, filename in CLIENT_ORDER:
        if filename in by_file and any(_rule_matches(rule, name=name, cache=cache)
                                       for rule in by_file[filename][1] if isinstance(rule, dict)):
            return group
    return None


def _compare(before, after, probes):
    """Probe names whose destination changed, and those that lost every
    match (orphaned: they would fall through to the proxy)."""
    changed, orphaned = [], []
    cache_before, cache_after = {}, {}
    for kind, probe in sorted(probes, key=str):
        if kind != "name":
            continue
        old, new = _destination(before, probe, cache_before), _destination(after, probe, cache_after)
        if old == new:
            continue
        (orphaned if new is None else changed).append({"name": probe, "before": old, "after": new})
    return changed, orphaned


def verify_exclusive(output_directory):
    """Names and addresses of the rule sets still matched by more than one
    destination, evaluated with the rewritten rules."""
    documents = _load_documents(output_directory)
    probes = _probes(documents)
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


def _probes(documents):
    """Names and addresses that exercise the rule sets: every entry, plus
    names in the regions of keywords and regexes."""
    probes, suffixes, keywords, regexes = set(), set(), set(), set()
    for _, _, rules in documents:
        index = RuleIndex(_flatten(rules))
        probes.update(("name", value) for _, value in index.entries())
        probes.update(("address", network.network_address) for network in index.networks)
        suffixes.update(index.suffixes)
        keywords.update(index.keywords)
        regexes.update(pattern for pattern, _ in index.regexes)
    # Pattern regions: names a keyword or regex matches under other suffixes.
    sample = sorted(suffixes)[::max(1, len(suffixes) // 400)]
    for keyword in keywords:
        for suffix in sample:
            probes.update({("name", f"{keyword}.{suffix}"), ("name", f"x{keyword}x.{suffix}")})
    for pattern in regexes:
        for name in _regex_samples(pattern):
            if "\0" not in name:
                probes.add(("name", name))
                continue
            probes.add(("name", name.replace("\0", "x")))
            if name.endswith("\0"):
                for suffix in sample:
                    probes.add(("name", name[:-1].replace("\0", "x") + suffix))
    return {(kind, probe) for kind, probe in probes if kind != "name" or HOSTNAME.fullmatch(probe)}


HOSTNAME = re.compile(r"[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*")


def _regex_samples(pattern, limit=12):
    """Names a regex matches, with "\\0" where it allows any text."""
    try:
        from re import _parser as parser
    except ImportError:  # Python < 3.11
        import sre_parse as parser
    constants = parser
    try:
        tree = parser.parse(pattern)
    except re.error:
        return []

    def options(op, av):
        name = str(op)
        if name == "LITERAL":
            return [chr(av).lower()]
        if name == "ANY":
            return ["\0", "."]
        if name == "IN":
            found = []
            for item_op, item in av:
                kind = str(item_op)
                if kind == "NEGATE":
                    return ["a"]
                if kind == "LITERAL":
                    found.append(chr(item).lower())
                elif kind == "RANGE":
                    found.append(chr(item[0]).lower())
                elif kind == "CATEGORY":
                    found.append("1" if "DIGIT" in str(item) else "a")
            return found[:3] or ["a"]
        if name in ("MAX_REPEAT", "MIN_REPEAT"):
            low, _, sub = av
            if len(sub) == 1 and str(sub[0][0]) == "ANY":
                return ["\0"]
            inner = sequence(sub)
            count = max(low, 1)
            return [text * count for text in inner][:limit]
        if name == "SUBPATTERN":
            return sequence(av[-1])
        if name == "BRANCH":
            found = []
            for item in av[1]:
                found.extend(sequence(item))
            return found[:limit]
        if name == "CATEGORY":
            return ["1" if "DIGIT" in str(av) else "a"]
        return [""]

    def sequence(items):
        outputs = [""]
        for op, av in items:
            outputs = [a + b for a in outputs for b in options(op, av)][:limit]
        return outputs

    del constants
    return [text.lstrip(".") for text in sequence(tree)]


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
