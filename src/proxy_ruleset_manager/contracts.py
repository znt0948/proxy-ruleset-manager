"""Strict input contracts for the ruleset types managed by this project."""

from dataclasses import dataclass, field
import ipaddress

from .utils import normalize_domain, normalize_domain_keyword, normalize_domain_suffix


RULESET_ALLOWED_FIELDS = {
    "geosite": frozenset({
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        # A small number of existing geosite upstreams are mixed domain/IP
        # lists. Keep their destination CIDRs instead of silently losing hits.
        "ip_cidr",
    }),
    "geoip": frozenset({"ip_cidr"}),
    "process": frozenset({"process_name"}),
}


@dataclass(frozen=True)
class RuleIssue:
    rule_index: int
    kind: str
    message: str


@dataclass
class RuleContractResult:
    rules: list[dict] = field(default_factory=list)
    issues: list[RuleIssue] = field(default_factory=list)

    @property
    def unsupported_count(self):
        return sum(issue.kind == "unsupported_rule" for issue in self.issues)

    @property
    def invalid_count(self):
        return sum(issue.kind.startswith("invalid_") for issue in self.issues)


def _has_value(value):
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict, str)):
        return bool(value)
    return True


def _normalize_string_values(value):
    if isinstance(value, str):
        raw_values = [value]
    elif isinstance(value, list):
        raw_values = value
    else:
        return None

    values = []
    for item in raw_values:
        if not isinstance(item, str):
            return None
        normalized = item.strip()
        if normalized:
            values.append(normalized)
    return values


def validate_ruleset_rules(rules, ruleset_type):
    """Validate rules without accepting a partial interpretation of a rule."""

    if ruleset_type not in RULESET_ALLOWED_FIELDS:
        raise ValueError(f"unknown ruleset type: {ruleset_type}")

    allowed_fields = RULESET_ALLOWED_FIELDS[ruleset_type]
    result = RuleContractResult()

    if not isinstance(rules, list):
        result.issues.append(RuleIssue(-1, "invalid_rule", "rules must be a list"))
        return result

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            result.issues.append(RuleIssue(index, "invalid_rule", "rule must be an object"))
            continue

        populated_fields = {key for key, value in rule.items() if _has_value(value)}
        # Empty list/object blocks are harmless upstream noise and have no
        # matching semantics. Drop them without treating the source as broken.
        if not populated_fields:
            continue
        unsupported_fields = sorted(populated_fields - allowed_fields)
        if unsupported_fields:
            result.issues.append(RuleIssue(
                index,
                "unsupported_rule",
                f"unsupported fields for {ruleset_type}: {', '.join(unsupported_fields)}",
            ))
            continue

        normalized_rule = {}
        invalid_reason = None
        for field_name in sorted(populated_fields):
            values = _normalize_string_values(rule[field_name])
            if values is None:
                invalid_reason = f"{field_name} must be a string or a list of strings"
                break

            if field_name == "ip_cidr":
                normalized_cidrs = []
                for value in values:
                    try:
                        normalized_cidrs.append(str(ipaddress.ip_network(value, strict=False)))
                    except ValueError:
                        result.issues.append(RuleIssue(
                            index,
                            "invalid_value",
                            f"invalid ip_cidr value: {value}",
                        ))
                values = normalized_cidrs

            if field_name == "domain_suffix":
                normalized_suffixes = []
                for value in values:
                    try:
                        normalized_suffixes.append(normalize_domain_suffix(value))
                    except ValueError as exc:
                        result.issues.append(RuleIssue(
                            index,
                            "invalid_value",
                            str(exc),
                        ))
                values = list(dict.fromkeys(normalized_suffixes))

            if field_name in {"domain", "domain_keyword"}:
                normalizer = (
                    normalize_domain
                    if field_name == "domain"
                    else normalize_domain_keyword
                )
                normalized_values = []
                for value in values:
                    try:
                        normalized_values.append(normalizer(value))
                    except ValueError as exc:
                        result.issues.append(RuleIssue(
                            index,
                            "invalid_value",
                            str(exc),
                        ))
                values = list(dict.fromkeys(normalized_values))

            if values:
                normalized_rule[field_name] = values

        if invalid_reason:
            result.issues.append(RuleIssue(index, "invalid_rule", invalid_reason))
            continue
        if not normalized_rule:
            result.issues.append(RuleIssue(index, "invalid_rule", "rule has no valid values"))
            continue

        result.rules.append(normalized_rule)

    return result


__all__ = [
    "RULESET_ALLOWED_FIELDS",
    "RuleContractResult",
    "RuleIssue",
    "validate_ruleset_rules",
]
