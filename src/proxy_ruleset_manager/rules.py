"""Rule merging, pruning, and de-duplication helpers."""

from .utils import (
    LOGICAL_RULE_KEYS,
    RULE_VALUE_FIELDS,
    Trie,
    TrieNode,
    collapse_cidr_values,
    compile_domain_regexes,
    convert_sets_to_lists,
    deduplicate_json,
    filter_domain_suffixes_with_trie,
    filter_domains_with_trie,
    load_json,
    make_hashable,
    merge_rules,
    prune_empty_rules,
    save_json,
    subtract_rules,
)

__all__ = [
    "LOGICAL_RULE_KEYS",
    "RULE_VALUE_FIELDS",
    "Trie",
    "TrieNode",
    "collapse_cidr_values",
    "compile_domain_regexes",
    "convert_sets_to_lists",
    "deduplicate_json",
    "filter_domain_suffixes_with_trie",
    "filter_domains_with_trie",
    "load_json",
    "make_hashable",
    "merge_rules",
    "prune_empty_rules",
    "save_json",
    "subtract_rules",
]
