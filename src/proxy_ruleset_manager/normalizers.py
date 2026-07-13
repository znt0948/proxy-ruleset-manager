"""Rule normalization helpers."""

from .utils import (
    clean_comment,
    clean_denied_domains,
    clean_json_data,
    deduplicate_adguard_lines,
    fix_domain_prefix,
    normalize_adguard_hosts_line,
    normalize_adguard_rule_line,
    normalize_domain,
    normalize_domain_keyword,
    normalize_domain_suffix,
    normalize_payload_items,
)

__all__ = [
    "clean_comment",
    "clean_denied_domains",
    "clean_json_data",
    "deduplicate_adguard_lines",
    "fix_domain_prefix",
    "normalize_adguard_hosts_line",
    "normalize_adguard_rule_line",
    "normalize_domain",
    "normalize_domain_keyword",
    "normalize_domain_suffix",
    "normalize_payload_items",
]
