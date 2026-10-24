"""Build deterministic reports for changes in published JSON rule sets."""

from collections import defaultdict
from datetime import datetime, timezone
import json
import os
import subprocess
import tempfile


MAX_ENTRIES_PER_FIELD = 5000
_STRUCTURAL_FIELDS = {"type", "mode", "rules"}
_PREFERRED_FIELDS = (
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
)
_NON_STRING_VALUE_PREFIX = "#json:"
_ESCAPED_STRING_VALUE_PREFIX = "#string:"


def _is_scalar(value):
    return value is not None and not isinstance(value, (dict, list))


def _value_key(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _field_sort_key(field):
    try:
        return (0, _PREFERRED_FIELDS.index(field))
    except ValueError:
        return (1, field)


def _persisted_value_key(value):
    if isinstance(value, str):
        if value.startswith((_NON_STRING_VALUE_PREFIX, _ESCAPED_STRING_VALUE_PREFIX)):
            return _ESCAPED_STRING_VALUE_PREFIX + value
        return value
    return _NON_STRING_VALUE_PREFIX + _value_key(value)


def _value_from_persisted_key(value):
    if not isinstance(value, str) or not value.startswith(_NON_STRING_VALUE_PREFIX):
        if isinstance(value, str) and value.startswith(_ESCAPED_STRING_VALUE_PREFIX):
            return value[len(_ESCAPED_STRING_VALUE_PREFIX):]
        return value
    try:
        return json.loads(value[len(_NON_STRING_VALUE_PREFIX):])
    except json.JSONDecodeError:
        return value


def iter_rule_values(rules):
    """Yield every scalar value in a rule tree, including unfamiliar fields."""
    if not isinstance(rules, list):
        return
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        for field, raw_values in rule.items():
            if field == "rules":
                yield from iter_rule_values(raw_values)
                continue
            if field in _STRUCTURAL_FIELDS:
                continue
            values = raw_values if isinstance(raw_values, list) else [raw_values]
            for value in values:
                if _is_scalar(value):
                    yield field, value


def collect_rule_values(rules):
    values_by_field = defaultdict(dict)
    for field, value in iter_rule_values(rules):
        values_by_field[field][_value_key(value)] = value
    return dict(values_by_field)


def build_source_provenance(source_records):
    """Map exact normalized values to the upstream URLs that contain them."""
    provenance = defaultdict(list)
    for record in source_records or []:
        if not isinstance(record, dict):
            continue
        source = record.get("url")
        if not isinstance(source, str) or not source:
            continue
        for field, value in iter_rule_values(record.get("rules", [])):
            key = (field, _value_key(value))
            if source not in provenance[key]:
                provenance[key].append(source)
    return dict(provenance)


def serialize_published_provenance(source_records, published_rules):
    """Persist exact sources only for values in the final published rules."""
    provenance = build_source_provenance(source_records)
    published_entries = sorted(
        set(iter_rule_values(published_rules)),
        key=lambda entry: (_field_sort_key(entry[0]), _value_key(entry[1])),
    )
    serialized = defaultdict(dict)
    for field, value in published_entries:
        sources = provenance.get((field, _value_key(value))) or ["unknown"]
        serialized[field][_persisted_value_key(value)] = sorted(sources)
    return {
        field: dict(sorted(values.items()))
        for field, values in sorted(serialized.items(), key=lambda item: _field_sort_key(item[0]))
    }


def provenance_from_source_entries(source_entries):
    provenance = defaultdict(list)
    if isinstance(source_entries, dict):
        for field, values_by_value in source_entries.items():
            if not isinstance(values_by_value, dict):
                continue
            for raw_value, sources in values_by_value.items():
                value = _value_from_persisted_key(raw_value)
                if not isinstance(sources, list):
                    sources = [sources]
                key = (field, _value_key(value))
                for source in sources or ["unknown"]:
                    if isinstance(source, str) and source and source not in provenance[key]:
                        provenance[key].append(source)
        return dict(provenance)

    for record in source_entries or []:
        if not isinstance(record, dict):
            continue
        if "field" in record and "value" in record:
            field = record["field"]
            value = record["value"]
            sources = record.get("sources", ["unknown"])
            if not isinstance(field, str) or not _is_scalar(value):
                continue
            if not isinstance(sources, list):
                sources = [sources]
            key = (field, _value_key(value))
            for source in sources or ["unknown"]:
                if isinstance(source, str) and source and source not in provenance[key]:
                    provenance[key].append(source)
            continue

        source = record.get("url")
        if not isinstance(source, str) or not source:
            continue
        entries_by_field = record.get("entries_by_field", {})
        if not isinstance(entries_by_field, dict):
            continue
        for field, raw_values in entries_by_field.items():
            values = raw_values if isinstance(raw_values, list) else [raw_values]
            for value in values:
                if not _is_scalar(value):
                    continue
                key = (field, _value_key(value))
                if source not in provenance[key]:
                    provenance[key].append(source)
    return dict(provenance)


def provenance_from_quality_report(quality_report):
    by_ruleset = {}
    if not isinstance(quality_report, dict):
        return by_ruleset
    for report in quality_report.get("rule_sets", []):
        if not isinstance(report, dict) or not report.get("ruleset"):
            continue
        ruleset = report["ruleset"]
        target = by_ruleset.setdefault(ruleset, {})
        for key, sources in provenance_from_source_entries(
            report.get("source_entries", [])
        ).items():
            target.setdefault(key, [])
            for source in sources:
                if source not in target[key]:
                    target[key].append(source)
    return by_ruleset


def _sources_for(provenance, field, value):
    return list(provenance.get((field, _value_key(value)), ["unknown"]))


def diff_rule_set(old_rules, new_rules, old_provenance=None,
                  new_provenance=None, value_limit=MAX_ENTRIES_PER_FIELD):
    old_values = collect_rule_values(old_rules)
    new_values = collect_rule_values(new_rules)
    old_provenance = old_provenance or {}
    new_provenance = new_provenance or {}
    fields = {}
    added_count = 0
    removed_count = 0

    fields_to_report = set(old_values) | set(new_values) | set(_PREFERRED_FIELDS)
    for field in sorted(fields_to_report, key=_field_sort_key):
        old_field = old_values.get(field, {})
        new_field = new_values.get(field, {})
        added_keys = sorted(set(new_field) - set(old_field))
        removed_keys = sorted(set(old_field) - set(new_field))
        added_count += len(added_keys)
        removed_count += len(removed_keys)
        fields[field] = {
            "added": [
                {
                    "value": new_field[key],
                    "sources": _sources_for(
                        new_provenance,
                        field,
                        new_field[key],
                    ),
                }
                for key in added_keys[:value_limit]
            ],
            "removed": [
                {
                    "value": old_field[key],
                    "sources": _sources_for(
                        old_provenance,
                        field,
                        old_field[key],
                    ),
                }
                for key in removed_keys[:value_limit]
            ],
            "added_count": len(added_keys),
            "removed_count": len(removed_keys),
            "added_truncated": len(added_keys) > value_limit,
            "removed_truncated": len(removed_keys) > value_limit,
        }

    return {
        "fields": fields,
        "added_count": added_count,
        "removed_count": removed_count,
    }


def _summary_label(ruleset):
    prefixes = (
        ("geosite-category-", ""),
        ("geoip-category-", "geoip-"),
        ("geosite-", ""),
        ("geoip-", "geoip-"),
    )
    for prefix, replacement in prefixes:
        if ruleset.startswith(prefix):
            return replacement + ruleset[len(prefix):]
    return ruleset


def summarize_rule_changes(rule_sets):
    parts = [
        f"{_summary_label(item['ruleset'])} +{item['added_count']}/-{item['removed_count']}"
        for item in rule_sets
        if item["added_count"] or item["removed_count"]
    ]
    return ", ".join(parts) if parts else "no changes"


def build_rule_changes(old_rule_sets, new_rule_sets, old_provenance=None,
                       new_provenance=None, value_limit=MAX_ENTRIES_PER_FIELD):
    old_rule_sets = old_rule_sets or {}
    new_rule_sets = new_rule_sets or {}
    old_provenance = old_provenance or {}
    new_provenance = new_provenance or {}
    results = []

    for ruleset in sorted(set(old_rule_sets) | set(new_rule_sets)):
        old_present = ruleset in old_rule_sets
        new_present = ruleset in new_rule_sets
        diff = diff_rule_set(
            old_rule_sets.get(ruleset, []),
            new_rule_sets.get(ruleset, []),
            old_provenance.get(ruleset, {}),
            new_provenance.get(ruleset, {}),
            value_limit=value_limit,
        )
        if not old_present:
            status = "added"
        elif not new_present:
            status = "deleted"
        elif diff["added_count"] or diff["removed_count"]:
            status = "changed"
        else:
            status = "unchanged"
        results.append({
            "ruleset": ruleset,
            "status": status,
            "added_count": diff["added_count"],
            "removed_count": diff["removed_count"],
            "fields": diff["fields"],
        })

    return {
        "summary": summarize_rule_changes(results),
        "rule_sets": results,
    }


def read_published_rule_sets(output_directory):
    rule_sets = {}
    if not os.path.isdir(output_directory):
        return rule_sets
    for filename in sorted(os.listdir(output_directory)):
        if not filename.endswith(".json"):
            continue
        with open(os.path.join(output_directory, filename), encoding="utf-8") as file:
            document = json.load(file)
        rule_sets[filename[:-5]] = document.get("rules", [])
    return rule_sets


def load_quality_report(report_file):
    try:
        with open(report_file, encoding="utf-8") as file:
            report = json.load(file)
        return report if isinstance(report, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def get_base_commit(root="."):
    github_sha = os.environ.get("GITHUB_SHA")
    if github_sha:
        return github_sha
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    commit = result.stdout.strip()
    return commit or None


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def write_rule_changes_report(report_file, baseline_rule_sets, output_directory,
                              old_quality_report=None,
                              source_records_by_ruleset=None,
                              base_commit=None, generated_at=None):
    current_rule_sets = read_published_rule_sets(output_directory)
    old_provenance = provenance_from_quality_report(old_quality_report or {})
    new_provenance = {
        ruleset: build_source_provenance(records)
        for ruleset, records in (source_records_by_ruleset or {}).items()
    }
    changes = build_rule_changes(
        baseline_rule_sets,
        current_rule_sets,
        old_provenance,
        new_provenance,
    )
    payload = {
        "version": 1,
        "generated_at": generated_at or utc_timestamp(),
        "base_commit": base_commit,
        "summary": changes["summary"],
        "rule_sets": changes["rule_sets"],
    }

    report_directory = os.path.dirname(report_file) or "."
    os.makedirs(report_directory, exist_ok=True)
    fd, temporary_path = tempfile.mkstemp(
        prefix=".rule-changes-",
        suffix=".json",
        dir=report_directory,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)
            file.write("\n")
        os.replace(temporary_path, report_file)
    finally:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)
    return payload


__all__ = [
    "MAX_ENTRIES_PER_FIELD",
    "build_rule_changes",
    "build_source_provenance",
    "collect_rule_values",
    "diff_rule_set",
    "get_base_commit",
    "iter_rule_values",
    "load_quality_report",
    "provenance_from_quality_report",
    "read_published_rule_sets",
    "serialize_published_provenance",
    "summarize_rule_changes",
    "utc_timestamp",
    "write_rule_changes_report",
]
