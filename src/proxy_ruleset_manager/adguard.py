"""Conservative AdGuard DNS rule optimization aligned with sing-box."""

from dataclasses import asdict, dataclass
import ipaddress

from .utils import (
    build_suffix_trie,
    filter_domain_suffixes_with_trie,
    normalize_domain,
    normalize_domain_suffix,
)


@dataclass(frozen=True)
class AdGuardRule:
    value: str
    kind: str
    allow: bool = False
    important: bool = False

    @property
    def bucket(self):
        return self.allow, self.important

    def render(self):
        prefix = "@@" if self.allow else ""
        modifier = "$important" if self.important else ""
        if self.kind == "exact":
            # A raw domain is exact only when every input line is a raw domain.
            # As soon as sing-box builds an AdGuard matcher for a mixed file,
            # the same text becomes an unanchored pattern. Always retain both
            # anchors so optimization cannot broaden the match accidentally.
            return f"{prefix}|{self.value}^{modifier}"
        if self.kind == "suffix":
            return f"{prefix}||{self.value}^{modifier}"
        return f"{self.value}{modifier}"


@dataclass
class AdGuardOptimizationStats:
    input_lines: int = 0
    skipped_comments_or_empty: int = 0
    unsupported_lines: int = 0
    exact_duplicates: int = 0
    exact_covered_by_suffix: int = 0
    suffix_covered_by_suffix: int = 0
    strict_exact_rules: int = 0
    strict_suffix_rules: int = 0
    preserved_complex_rules: int = 0
    output_lines: int = 0

    def to_dict(self):
        return asdict(self)


def _split_supported_modifiers(value):
    """Match sing-box's supported DNS-only modifier subset."""
    if value.startswith("/") or "$" not in value:
        return value, False

    body, modifier_text = value.split("$", 1)
    important = False
    for raw_modifier in modifier_text.split(","):
        modifier = raw_modifier.strip().lower()
        if modifier == "important":
            important = True
        elif modifier.startswith("dnsrewrite="):
            try:
                rewrite_address = ipaddress.ip_address(
                    modifier.split("=", 1)[1]
                )
            except ValueError:
                return None
            if not rewrite_address.is_unspecified:
                return None
            # sing-box treats an unspecified rewrite address as the same
            # blocking match and drops the rewrite payload in a headless rule.
            continue
        else:
            return None
    return body, important


def _parse_hosts_exact(value):
    parts = value.split()
    if len(parts) < 2 or parts[0] != "0.0.0.0":
        return None
    try:
        return normalize_domain(parts[1])
    except ValueError:
        return None


def _is_ip_or_cidr(value):
    try:
        ipaddress.ip_network(value.rstrip("."), strict=False)
        return True
    except ValueError:
        return False


def _is_supported_complex_domain_pattern(body):
    """Reject the same non-DNS constructs that sing-box discards."""
    candidate = body
    if candidate.startswith("@@"):
        candidate = candidate[2:]
    candidate = candidate.rstrip("|")
    if candidate.startswith("||"):
        candidate = candidate[2:]
    elif candidate.startswith("|"):
        candidate = candidate[1:]
    if candidate.endswith("^"):
        candidate = candidate[:-1]
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]
    if (
        not candidate
        or "/" in candidate
        or "?" in candidate
        or "&" in candidate
        or any(character in candidate for character in "[]()!#~")
        or ":" in candidate
        or _is_ip_or_cidr(candidate)
    ):
        return False

    domain_check = candidate.replace("*", "x")
    if domain_check.startswith((".", "-")):
        domain_check = "r" + domain_check
    try:
        normalize_domain(domain_check)
    except ValueError:
        return False
    return True


def parse_adguard_dns_rule(line):
    """Parse only semantics sing-box can use for DNS matching."""
    value = str(line).strip()
    if not value or value.startswith(("!", "#", "[")):
        return None, "skipped"

    hosts_domain = _parse_hosts_exact(value)
    if hosts_domain is not None:
        return AdGuardRule(hosts_domain, "exact"), "parsed"

    # A hosts line with any other address is intentionally unsupported by this
    # project even if the address itself is syntactically valid.
    parts = value.split()
    if len(parts) >= 2:
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            pass
        else:
            return None, "unsupported"

    modifier_result = _split_supported_modifiers(value)
    if modifier_result is None:
        return None, "unsupported"
    body, important = modifier_result

    allow = body.startswith("@@")
    match_body = body[2:] if allow else body
    match_body = match_body.rstrip("|")

    if match_body.startswith("/") and match_body.endswith("/"):
        regex = match_body[1:-1]
        if not regex or _looks_like_ip_regex(regex):
            return None, "unsupported"
        return AdGuardRule(
            f"{'@@' if allow else ''}/{regex}/",
            "regex",
            allow=allow,
            important=False,
        ), "parsed"

    syntax_check = match_body
    if "://" in syntax_check:
        syntax_check = syntax_check.split("://", 1)[1]
    if (
        "/" in syntax_check
        or "?" in syntax_check
        or "&" in syntax_check
        or any(character in syntax_check for character in "[]()!#~")
    ):
        return None, "unsupported"

    if match_body.startswith("||") and match_body.endswith("^"):
        domain = match_body[2:-1]
        if "*" not in domain:
            if _is_ip_or_cidr(domain):
                return None, "unsupported"
            try:
                domain = normalize_domain_suffix(domain)
            except ValueError:
                return None, "unsupported"
            return AdGuardRule(domain, "suffix", allow, important), "parsed"

    if match_body.startswith("|") and match_body.endswith("^"):
        domain = match_body[1:-1]
        if "*" not in domain:
            if _is_ip_or_cidr(domain):
                return None, "unsupported"
            try:
                domain = normalize_domain(domain)
            except ValueError:
                return None, "unsupported"
            return AdGuardRule(domain, "exact", allow, important), "parsed"

    # A bare domain is recognized as an exact rule by sing-box only before
    # modifier parsing, so keep modified bare domains as complex patterns.
    if (
        not allow
        and "$" not in value
        and not any(character in match_body for character in "|^*")
    ):
        try:
            domain = normalize_domain(match_body)
        except ValueError:
            pass
        else:
            if not _is_ip_or_cidr(domain):
                return AdGuardRule(domain, "exact"), "parsed"

    if not _is_supported_complex_domain_pattern(body):
        return None, "unsupported"
    canonical_body = body.lower()
    return AdGuardRule(
        canonical_body,
        "complex",
        allow=allow,
        important=important,
    ), "parsed"


def _looks_like_ip_regex(regex):
    candidate = regex
    for prefix in (r"(http?:\/\/)", r"(https?:\/\/)", "^"):
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix):]
            break
    first = candidate.split(r"\.", 1)[0].split(".", 1)[0]
    return first.isdigit() and 0 <= int(first) <= 255


def optimize_adguard_lines(lines, return_stats=False):
    """Optimize strict DNS rules without crossing AdGuard priority buckets."""
    stats = AdGuardOptimizationStats()
    parsed_rules = []
    seen = set()

    for line in lines:
        stats.input_lines += 1
        rule, status = parse_adguard_dns_rule(line)
        if status == "skipped":
            stats.skipped_comments_or_empty += 1
            continue
        if status == "unsupported":
            stats.unsupported_lines += 1
            continue

        rendered = rule.render()
        if rendered in seen:
            stats.exact_duplicates += 1
            continue
        seen.add(rendered)
        parsed_rules.append(rule)

    reduced_suffixes = {}
    suffix_tries = {}
    for bucket in {(rule.bucket) for rule in parsed_rules}:
        suffixes = {
            rule.value
            for rule in parsed_rules
            if rule.bucket == bucket and rule.kind == "suffix"
        }
        reduced = filter_domain_suffixes_with_trie(suffixes)
        reduced_suffixes[bucket] = reduced
        suffix_tries[bucket] = build_suffix_trie(reduced)
        stats.suffix_covered_by_suffix += len(suffixes) - len(reduced)

    optimized = []
    for rule in parsed_rules:
        if rule.kind == "suffix":
            if rule.value not in reduced_suffixes[rule.bucket]:
                continue
            stats.strict_suffix_rules += 1
        elif rule.kind == "exact":
            if suffix_tries[rule.bucket].has_suffix(rule.value):
                stats.exact_covered_by_suffix += 1
                continue
            stats.strict_exact_rules += 1
        else:
            stats.preserved_complex_rules += 1
        optimized.append(rule.render())

    stats.output_lines = len(optimized)
    if return_stats:
        return optimized, stats.to_dict()
    return optimized


__all__ = [
    "AdGuardOptimizationStats",
    "AdGuardRule",
    "optimize_adguard_lines",
    "parse_adguard_dns_rule",
]
