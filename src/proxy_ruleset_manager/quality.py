"""Quality metrics and source provenance for structured rulesets."""

from collections import defaultdict
import ipaddress
from itertools import combinations

from .utils import LOGICAL_RULE_KEYS, RULE_VALUE_FIELDS, count_rule_entries


class _SuffixCoverageIndex:
    """Small reversed-label trie for root-and-subdomain suffix semantics."""

    _TERMINAL = ""

    def __init__(self, suffixes=()):
        self.root = {}
        for suffix in suffixes:
            node = self.root
            for label in reversed(suffix.split(".")):
                node = node.setdefault(label, {})
            node[self._TERMINAL] = True

    def covers(self, domain):
        node = self.root
        for label in reversed(domain.split(".")):
            node = node.get(label)
            if node is None:
                return False
            if self._TERMINAL in node:
                return True
        return False


class SemanticCoverageIndex:
    """Index the rule fields where coverage can be proven without inference."""

    def __init__(self, rules):
        entries = defaultdict(set)
        for field, value in iter_rule_entries(rules):
            entries[field].add(value)
        self.entries = entries
        self.suffixes = _SuffixCoverageIndex(entries["domain_suffix"])
        self.networks = {
            4: set(),
            6: set(),
        }
        for value in entries["ip_cidr"]:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            self.networks[network.version].add(network)

    def covers(self, field, value):
        if field == "domain":
            return value in self.entries[field] or self.suffixes.covers(value)
        if field == "domain_suffix":
            return self.suffixes.covers(value)
        if field == "ip_cidr":
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return False
            candidates = self.networks[network.version]
            current = network
            while True:
                if current in candidates:
                    return True
                if current.prefixlen == 0:
                    return False
                current = current.supernet()
        return value in self.entries[field]


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


def summarize_semantic_overlap(candidate_rules, reference_rules):
    """Count candidate entries provably covered by a reference rule union.

    Keyword and regex fields intentionally use exact equality only.  Inferring
    substring or regular-expression coverage would be too broad for an
    automated quality report.
    """
    index = SemanticCoverageIndex(reference_rules)
    by_field = defaultdict(lambda: {"entries": 0, "covered": 0})
    total_entries = 0
    total_covered = 0
    for field, value in sorted(set(iter_rule_entries(candidate_rules))):
        total_entries += 1
        by_field[field]["entries"] += 1
        if index.covers(field, value):
            total_covered += 1
            by_field[field]["covered"] += 1

    for counts in by_field.values():
        counts["uncovered"] = counts["entries"] - counts["covered"]
    return {
        "entries": total_entries,
        "covered": total_covered,
        "uncovered": total_entries - total_covered,
        "covered_ratio": round(total_covered / total_entries, 6)
        if total_entries else 0.0,
        "by_field": dict(sorted(by_field.items())),
    }


def analyze_light_source_candidates(source_records, target_rules,
                                    conflict_rule_sets=None):
    """Measure source coverage of a published target and build a greedy order.

    The target represents the corrected, optimized ruleset semantics.  The
    greedy order is descriptive: it selects the source covering the largest
    number of still-uncovered published entries.  It must not be used as an
    automatic deletion decision.
    """
    conflict_rule_sets = conflict_rule_sets or {}
    target_entries = sorted(set(iter_rule_entries(target_rules)))
    conflict_indexes = {
        name: SemanticCoverageIndex(rules)
        for name, rules in sorted(conflict_rule_sets.items())
    }

    coverage_by_source = {}
    source_summaries = []
    for record in source_records:
        url = record["url"]
        rules = record["rules"]
        index = SemanticCoverageIndex(rules)
        covered_indexes = {
            entry_index
            for entry_index, (field, value) in enumerate(target_entries)
            if index.covers(field, value)
        }
        coverage_by_source[url] = covered_indexes

        conflicts = {}
        source_entries = sorted(set(iter_rule_entries(rules)))
        for name, conflict_index in conflict_indexes.items():
            covered = sum(
                1
                for field, value in source_entries
                if conflict_index.covers(field, value)
            )
            conflicts[name] = {
                "covered_source_entries": covered,
                "source_entry_ratio": round(covered / len(source_entries), 6)
                if source_entries else 0.0,
            }

        source_summaries.append({
            "url": url,
            "source_entries": len(source_entries),
            "correction_removed_entries": record.get(
                "correction_removed_entries", 0
            ),
            "published_target_entries_covered": len(covered_indexes),
            "published_target_coverage_ratio": round(
                len(covered_indexes) / len(target_entries), 6
            ) if target_entries else 0.0,
            "classification_conflicts": conflicts,
        })

    coverage_frequency = defaultdict(int)
    for covered_indexes in coverage_by_source.values():
        for entry_index in covered_indexes:
            coverage_frequency[entry_index] += 1
    summaries_by_url = {summary["url"]: summary for summary in source_summaries}
    for url, covered_indexes in coverage_by_source.items():
        exclusive = sum(
            1 for entry_index in covered_indexes
            if coverage_frequency[entry_index] == 1
        )
        summaries_by_url[url]["exclusive_published_target_entries"] = exclusive

    def build_greedy_order(eligible_urls):
        remaining = set(range(len(target_entries)))
        selected = set()
        order = []
        while remaining:
            candidates = [
                (
                    len(coverage_by_source[url] & remaining),
                    url,
                )
                for url in eligible_urls
                if url not in selected
            ]
            if not candidates:
                break
            marginal, selected_url = min(
                candidates,
                key=lambda item: (-item[0], item[1]),
            )
            if marginal == 0:
                break
            selected.add(selected_url)
            remaining -= coverage_by_source[selected_url]
            cumulative = len(target_entries) - len(remaining)
            order.append({
                "rank": len(order) + 1,
                "url": selected_url,
                "marginal_target_entries": marginal,
                "cumulative_target_entries": cumulative,
                "cumulative_target_coverage_ratio": round(
                    cumulative / len(target_entries), 6
                ) if target_entries else 0.0,
            })
        return order, remaining

    greedy_order, remaining = build_greedy_order(coverage_by_source)
    bulk_threshold = 10000
    non_bulk_urls = {
        summary["url"]
        for summary in source_summaries
        if summary["source_entries"] <= bulk_threshold
    }
    non_bulk_order, non_bulk_remaining = build_greedy_order(non_bulk_urls)

    greedy_rank = {item["url"]: item["rank"] for item in greedy_order}
    for summary in source_summaries:
        summary["greedy_rank"] = greedy_rank.get(summary["url"])

    source_summaries.sort(
        key=lambda item: (
            item["greedy_rank"] is None,
            item["greedy_rank"] or 0,
            item["url"],
        )
    )
    return {
        "method": (
            "semantic coverage of corrected published entries; keyword and "
            "regex coverage is exact-only"
        ),
        "published_target_entries": len(target_entries),
        "sources": source_summaries,
        "greedy_coverage_order": greedy_order,
        "uncovered_target_entries": len(remaining),
        "non_bulk_scenario": {
            "maximum_source_entries": bulk_threshold,
            "excluded_sources": sorted(set(coverage_by_source) - non_bulk_urls),
            "greedy_coverage_order": non_bulk_order,
            "covered_target_entries": len(target_entries) - len(non_bulk_remaining),
            "target_coverage_ratio": round(
                (len(target_entries) - len(non_bulk_remaining)) /
                len(target_entries),
                6,
            ) if target_entries else 0.0,
        },
    }


__all__ = [
    "SemanticCoverageIndex",
    "analyze_light_source_candidates",
    "build_provenance",
    "count_entries_by_field",
    "iter_rule_entries",
    "summarize_semantic_overlap",
    "summarize_provenance",
]
