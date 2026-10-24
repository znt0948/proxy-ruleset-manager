import json
import os
import tempfile
import unittest

from proxy_ruleset_manager.changes import (
    MAX_ENTRIES_PER_FIELD,
    build_rule_changes,
    build_source_provenance,
    provenance_from_quality_report,
    serialize_published_provenance,
    write_rule_changes_report,
)
from proxy_ruleset_manager.pipeline import RuleParser


class RuleChangesTests(unittest.TestCase):
    @staticmethod
    def _result(report, ruleset):
        return next(item for item in report["rule_sets"] if item["ruleset"] == ruleset)

    def test_new_rule_set_is_attributed_to_new_sources(self):
        new_rules = {
            "geosite-category-test": [{
                "domain": ["new.example"],
                "process_name": ["ExampleApp"],
            }],
        }
        source_records = [{
            "url": "source-a",
            "rules": new_rules["geosite-category-test"],
        }, {
            "url": "source-b",
            "rules": new_rules["geosite-category-test"],
        }]

        report = build_rule_changes(
            {},
            new_rules,
            new_provenance={
                "geosite-category-test": build_source_provenance(source_records),
            },
        )

        result = self._result(report, "geosite-category-test")
        self.assertEqual(result["status"], "added")
        self.assertEqual(result["fields"]["domain"]["added"], [{
            "value": "new.example",
            "sources": ["source-a", "source-b"],
        }])
        self.assertEqual(result["fields"]["process_name"]["added_count"], 1)

    def test_deleted_rule_set_uses_previous_quality_sources(self):
        old_rules = {
            "geosite-old": [{
                "domain": ["gone.example"],
                "ip_cidr": ["192.0.2.0/24"],
            }],
        }
        old_quality = {
            "rule_sets": [{
                "ruleset": "geosite-old",
                "source_entries": {
                    "domain": {"gone.example": ["source-old"]},
                    "ip_cidr": {"192.0.2.0/24": ["source-old"]},
                },
            }],
        }

        report = build_rule_changes(
            old_rules,
            {},
            old_provenance=provenance_from_quality_report(old_quality),
        )

        result = self._result(report, "geosite-old")
        self.assertEqual(result["status"], "deleted")
        self.assertEqual(
            result["fields"]["domain"]["removed"][0]["sources"],
            ["source-old"],
        )
        self.assertEqual(
            result["fields"]["ip_cidr"]["removed"][0]["sources"],
            ["source-old"],
        )

    def test_persisted_provenance_contains_only_final_published_values(self):
        source_records = [{
            "url": "source-b",
            "rules": [{"domain": ["kept.example", "discarded.example"]}],
        }, {
            "url": "source-a",
            "rules": [{"domain": ["kept.example"]}],
        }]

        self.assertEqual(
            serialize_published_provenance(
                source_records,
                [{"domain": ["kept.example", "generated.example"]}],
            ),
            {
                "domain": {
                    "generated.example": ["unknown"],
                    "kept.example": ["source-a", "source-b"],
                },
            },
        )

    def test_quality_report_uses_final_published_rules_for_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            output_directory = os.path.join(directory, "singbox")
            os.makedirs(output_directory)
            with open(
                os.path.join(output_directory, "geosite-test.json"),
                "w",
                encoding="utf-8",
            ) as file:
                json.dump({
                    "version": 1,
                    "rules": [{"domain": ["kept.example"]}],
                }, file)

            parser = RuleParser(capture_source_records=True)
            parser.quality_reports = [{
                "ruleset": "geosite-test",
                "type": "geosite",
            }]
            parser.source_records_by_ruleset = {
                "geosite-test": [{
                    "url": "source-a",
                    "rules": [{
                        "domain": ["kept.example", "not-published.example"],
                    }],
                }],
            }
            report_path = os.path.join(directory, "ruleset-quality.json")
            parser.write_quality_report(output_directory, report_path)

            with open(report_path, encoding="utf-8") as file:
                report = json.load(file)
            self.assertEqual(
                report["rule_sets"][0]["source_entries"],
                {"domain": {"kept.example": ["source-a"]}},
            )

    def test_unchanged_rule_set_has_empty_changes_for_each_field(self):
        rules = {
            "geosite-same": [{
                "domain": ["same.example"],
                "custom_field": ["same-value"],
            }],
        }

        result = self._result(build_rule_changes(rules, rules), "geosite-same")
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(result["added_count"], 0)
        self.assertEqual(result["removed_count"], 0)
        self.assertEqual(result["fields"]["custom_field"]["added"], [])
        self.assertFalse(result["fields"]["domain"]["removed_truncated"])
        self.assertEqual(
            set(result["fields"]),
            {
                "domain",
                "domain_suffix",
                "domain_keyword",
                "domain_regex",
                "ip_cidr",
                "custom_field",
            },
        )

    def test_each_field_is_truncated_after_5000_values(self):
        values = [
            f"item-{number}.example"
            for number in range(MAX_ENTRIES_PER_FIELD + 1)
        ]
        report = build_rule_changes(
            {},
            {"geosite-large": [{"domain": values}]},
        )

        field = self._result(report, "geosite-large")["fields"]["domain"]
        self.assertEqual(field["added_count"], MAX_ENTRIES_PER_FIELD + 1)
        self.assertEqual(len(field["added"]), MAX_ENTRIES_PER_FIELD)
        self.assertTrue(field["added_truncated"])

    def test_unknown_source_is_used_when_no_exact_source_exists(self):
        report = build_rule_changes(
            {},
            {"geosite-test": [{"domain": ["generated.example"]}]},
            new_provenance={"geosite-test": build_source_provenance([{
                "url": "source-a",
                "rules": [{"domain": ["different.example"]}],
            }])},
        )

        added = self._result(report, "geosite-test")["fields"]["domain"]["added"]
        self.assertEqual(added[0]["sources"], ["unknown"])

    def test_report_step_does_not_change_generated_json_or_srs_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            output_directory = os.path.join(directory, "singbox")
            os.makedirs(output_directory)
            json_path = os.path.join(output_directory, "geosite-test.json")
            srs_path = os.path.join(output_directory, "geosite-test.srs")
            with open(json_path, "w", encoding="utf-8") as file:
                json.dump({
                    "version": 1,
                    "rules": [{"domain": ["new.example"]}],
                }, file, indent=4)
                file.write("\n")
            with open(srs_path, "wb") as file:
                file.write(b"compiled rule-set bytes")

            before = {}
            for path in (json_path, srs_path):
                with open(path, "rb") as file:
                    before[path] = file.read()

            report_path = os.path.join(directory, "report", "rule-changes.json")
            write_rule_changes_report(
                report_path,
                {"geosite-test": [{"domain": ["old.example"]}]},
                output_directory,
                source_records_by_ruleset={"geosite-test": [{
                    "url": "source-a",
                    "rules": [{"domain": ["new.example"]}],
                }]},
                base_commit="base-sha",
                generated_at="2026-01-01T00:00:00Z",
            )

            after = {}
            for path in (json_path, srs_path):
                with open(path, "rb") as file:
                    after[path] = file.read()
            self.assertEqual(before, after)
            self.assertTrue(os.path.exists(report_path))


if __name__ == "__main__":
    unittest.main()
