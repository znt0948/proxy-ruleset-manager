"""Quality metrics and exact source provenance for structured rulesets."""

from collections import defaultdict
from itertools import combinations

from .utils import LOGICAL_RULE_KEYS, RULE_VALUE_FIELDS, count_rule_entries


def iter_rule_entries(rules):
    for rule in rules:
        if not isinstance(rule, dict) or LOGICAL_RULE_KEYS.issubset(rule.keys()):
            continue
        for field in RULE_VALUE_FIELDS:
            values = rule.get(field, [])
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                continue
            for value in values:
                if isinstance(value, str) and value:
                    yield field, value


def build_provenance(source_records):
    """Map normalized exact entries to the ordered upstream URLs providing them."""
    provenance = defaultdict(list)
    for record in source_records:
        source = record["url"]
        for entry in iter_rule_entries(record["rules"]):
            if source not in provenance[entry]:
                provenance[entry].append(source)
    return provenance


def summarize_provenance(provenance, final_rules, source_urls, sample_limit=50):
    """Summarize exact provenance without bloating published rule artifacts."""
    final_entries = sorted(set(iter_rule_entries(final_rules)))
    source_output_contribution = {source: 0 for source in source_urls}
    multi_source_samples = []
    multi_source_entry_count = 0
    unattributed_entry_count = 0

    for field, value in final_entries:
        sources = provenance.get((field, value), [])
        if not sources:
            # CIDR collapsing can synthesize a parent prefix that did not exist
            # verbatim in any input. It is valid but has no exact attribution.
            unattributed_entry_count += 1
            continue
        for source in sources:
            source_output_contribution[source] += 1
        if len(sources) > 1:
            multi_source_entry_count += 1
            if len(multi_source_samples) < sample_limit:
                multi_source_samples.append({
                    "field": field,
                    "value": value,
                    "sources": sources,
                })

    pair_overlap = defaultdict(int)
    normalized_overlap_entry_count = 0
    for sources in provenance.values():
        if len(sources) < 2:
            continue
        normalized_overlap_entry_count += 1
        for left, right in combinations(sorted(sources), 2):
            pair_overlap[(left, right)] += 1

    source_pair_overlaps = [
        {"sources": [left, right], "entry_count": count}
        for (left, right), count in sorted(
            pair_overlap.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]

    return {
        "tracked_normalized_entries": len(provenance),
        "published_entries": count_rule_entries(final_rules),
        "published_entries_with_multiple_exact_sources": multi_source_entry_count,
        "published_entries_without_exact_source": unattributed_entry_count,
        "normalized_entries_shared_by_sources": normalized_overlap_entry_count,
        "source_output_contribution": source_output_contribution,
        "source_pair_overlaps": source_pair_overlaps,
        "multi_source_samples": multi_source_samples,
    }


def count_entries_by_field(rules):
    counts = defaultdict(int)
    for field, _ in iter_rule_entries(rules):
        counts[field] += 1
    return dict(sorted(counts.items()))


__all__ = [
    "build_provenance",
    "count_entries_by_field",
    "iter_rule_entries",
    "summarize_provenance",
]
