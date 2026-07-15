import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import pandas as pd

from proxy_ruleset_manager.adguard import (
    optimize_adguard_lines,
    parse_adguard_dns_rule,
)
from proxy_ruleset_manager.contracts import validate_ruleset_rules
from proxy_ruleset_manager.pipeline import RuleParser
from proxy_ruleset_manager.quality import (
    analyze_light_source_candidates,
    build_provenance,
    summarize_provenance,
    summarize_semantic_overlap,
)
from proxy_ruleset_manager.utils import (
    clash_domain_rule,
    clean_denied_domains,
    collapse_cidr_values,
    convert_json_to_clash,
    deduplicate_exact_rules,
    deduplicate_json,
    filter_domain_suffixes_with_trie,
    normalize_domain,
    normalize_domain_keyword,
    normalize_domain_suffix,
)


def matches_destination_domain(rules, domain):
    domain = domain.lower().rstrip(".")
    for rule in rules:
        if domain in rule.get("domain", []):
            return True
        if any(
            domain == suffix or domain.endswith("." + suffix)
            for suffix in rule.get("domain_suffix", [])
        ):
            return True
        if any(keyword in domain for keyword in rule.get("domain_keyword", [])):
            return True
        if any(re.search(pattern, domain) for pattern in rule.get("domain_regex", [])):
            return True
    return False


class AdGuardOptimizationTests(unittest.TestCase):
    def test_equivalent_exact_domain_forms_are_deduplicated(self):
        rules, stats = optimize_adguard_lines([
            "Example.COM",
            "0.0.0.0 example.com",
            "|example.com^",
        ], return_stats=True)

        self.assertEqual(rules, ["|example.com^"])
        self.assertEqual(stats["exact_duplicates"], 2)

    def test_raw_domain_is_anchored_before_mixing_with_adguard_patterns(self):
        rules = optimize_adguard_lines([
            "example.com",
            "example.net^",
        ])

        self.assertEqual(rules, ["|example.com^", "example.net^"])

    def test_suffix_coverage_is_isolated_by_priority_bucket(self):
        rules, stats = optimize_adguard_lines([
            "||example.com^",
            "||ads.example.com^",
            "tracker.example.com",
            "@@||allow.example.com^",
            "@@|api.allow.example.com^",
            "||ads.example.com^$important",
            "@@||private.example.com^$important",
        ], return_stats=True)

        self.assertEqual(rules, [
            "||example.com^",
            "@@||allow.example.com^",
            "||ads.example.com^$important",
            "@@||private.example.com^$important",
        ])
        self.assertEqual(stats["suffix_covered_by_suffix"], 1)
        self.assertEqual(stats["exact_covered_by_suffix"], 2)

    def test_dnsrewrite_is_canonicalized_and_important_is_preserved(self):
        rules = optimize_adguard_lines([
            "||Example.com^$DNSRewrite=0.0.0.0,Important",
            "||example.com^$dnsrewrite=::,important",
            "||example.com^$important",
        ])

        self.assertEqual(rules, ["||example.com^$important"])

    def test_complex_and_regex_rules_only_receive_exact_deduplication(self):
        rules = optimize_adguard_lines([
            "example.net^",
            "EXAMPLE.NET^",
            "||example.edu",
            "/^ad[0-9]+\\.example$/",
        ])

        self.assertEqual(rules, [
            "example.net^",
            "||example.edu",
            "/^ad[0-9]+\\.example$/",
        ])

    def test_non_dns_and_unsupported_sing_box_rules_are_removed(self):
        lines = [
            "! comment",
            "# comment",
            "[Adblock Plus 2.0]",
            "||example.com/path^",
            "||example.com^$third-party",
            "example.com##.advert",
            "127.0.0.1 example.com",
            r"/^192\.0\.2\./",
            "||keep.example^",
        ]
        rules, stats = optimize_adguard_lines(lines, return_stats=True)

        self.assertEqual(rules, ["||keep.example^"])
        self.assertEqual(stats["skipped_comments_or_empty"], 3)
        self.assertEqual(stats["unsupported_lines"], 5)

    def test_anchored_ip_addresses_are_not_treated_as_domains(self):
        rules, stats = optimize_adguard_lines([
            "||1.0.140.1^",
            "|2001:db8::1^",
            "||192.0.2.0/24^",
            "||keep.example^",
        ], return_stats=True)

        self.assertEqual(rules, ["||keep.example^"])
        self.assertEqual(stats["unsupported_lines"], 3)

    def test_modified_bare_domain_keeps_sing_box_pattern_semantics(self):
        rule, status = parse_adguard_dns_rule("example.com$important")

        self.assertEqual(status, "parsed")
        self.assertEqual(rule.kind, "complex")
        self.assertEqual(rule.render(), "example.com$important")

    @unittest.skipUnless(shutil.which("sing-box"), "sing-box is not installed")
    def test_optimized_rules_convert_with_sing_box(self):
        rules = optimize_adguard_lines([
            "0.0.0.0 exact.example",
            "||suffix.example^",
            "@@||allow.suffix.example^",
            "||important.example^$important",
            r"/^regex[0-9]+\.example$/",
        ])

        with tempfile.TemporaryDirectory() as directory:
            input_path = os.path.join(directory, "rules.txt")
            output_path = os.path.join(directory, "rules.srs")
            with open(input_path, "w", encoding="utf-8") as file:
                file.write("\n".join(rules))
            subprocess.run([
                "sing-box",
                "rule-set",
                "convert",
                "--type",
                "adguard",
                "--output",
                output_path,
                input_path,
            ], check=True, capture_output=True, text=True)

            self.assertTrue(os.path.exists(output_path))
            self.assertGreater(os.path.getsize(output_path), 0)


class RuleContractTests(unittest.TestCase):
    def test_geosite_accepts_only_domain_match_fields(self):
        result = validate_ruleset_rules([
            {"domain": ["example.com"], "domain_suffix": ["example.net"]},
            {"domain_suffix": ["example.org"], "network": ["udp"]},
        ], "geosite")

        self.assertEqual(result.rules, [{
            "domain": ["example.com"],
            "domain_suffix": ["example.net"],
        }])
        self.assertEqual(result.unsupported_count, 1)
        self.assertIn("network", result.issues[0].message)

    def test_geosite_keeps_cidr_from_existing_mixed_upstreams(self):
        result = validate_ruleset_rules([
            {"domain_suffix": ["example.com"]},
            {"ip_cidr": ["2001:db8::/32"]},
        ], "geosite")

        self.assertEqual(result.issues, [])
        self.assertEqual(result.rules[1], {"ip_cidr": ["2001:db8::/32"]})

    def test_geoip_keeps_ipv6_and_reports_invalid_values(self):
        result = validate_ruleset_rules([
            {"ip_cidr": ["2001:db8::1/32", "192.0.2.7/24", "invalid"]},
        ], "geoip")

        self.assertEqual(result.rules, [{
            "ip_cidr": ["2001:db8::/32", "192.0.2.0/24"],
        }])
        self.assertEqual(result.invalid_count, 1)

    def test_suffix_forms_are_promoted_and_deduplicated(self):
        result = validate_ruleset_rules([{
            "domain_suffix": ["example.com", ".Example.com", "+.example.com"],
        }], "geosite")

        self.assertEqual(result.issues, [])
        self.assertEqual(result.rules, [{"domain_suffix": ["example.com"]}])

    def test_wildcard_domain_is_rejected_as_suffix(self):
        result = validate_ruleset_rules([{
            "domain_suffix": ["*.example.com"],
        }], "geosite")

        self.assertEqual(result.rules, [])
        self.assertGreaterEqual(result.invalid_count, 1)
        self.assertIn("wildcard", result.issues[0].message)

    def test_empty_upstream_rule_is_ignored_as_noop(self):
        result = validate_ruleset_rules([
            {"domain": []},
            {},
            {"domain_suffix": ["example.com"]},
        ], "geosite")

        self.assertEqual(result.issues, [])
        self.assertEqual(result.rules, [{"domain_suffix": ["example.com"]}])

    def test_domain_and_keyword_are_lowercased_and_deduplicated(self):
        result = validate_ruleset_rules([{
            "domain": ["Example.COM", "example.com."],
            "domain_keyword": ["Google", "google"],
            "domain_regex": ["Example\\.COM$"],
        }], "geosite")

        self.assertEqual(result.issues, [])
        self.assertEqual(result.rules, [{
            "domain": ["example.com"],
            "domain_keyword": ["google"],
            "domain_regex": ["Example\\.COM$"],
        }])

    def test_domain_ip_values_are_reclassified_as_cidr(self):
        result = validate_ruleset_rules([{
            "domain": ["0.0.0.0", "2001:db8::1", "192.0.2.7/24"],
        }], "geosite")

        self.assertEqual(result.issues, [])
        self.assertEqual(result.rules, [{
            "ip_cidr": ["0.0.0.0/32", "2001:db8::1/128", "192.0.2.0/24"],
        }])

    def test_unicode_domain_is_normalized_to_idna(self):
        result = validate_ruleset_rules([{
            "domain": ["例子.测试"],
            "domain_suffix": [".食狮.com.cn"],
        }], "geosite")

        self.assertEqual(result.issues, [])
        self.assertEqual(result.rules, [{
            "domain": ["xn--fsqu00a.xn--0zwm56d"],
            "domain_suffix": ["xn--85x722f.com.cn"],
        }])

    def test_url_and_domain_with_port_are_rejected(self):
        result = validate_ruleset_rules([{
            "domain": ["https://example.com/path", "example.com:443"],
        }], "geosite")

        self.assertEqual(result.rules, [])
        self.assertEqual(result.invalid_count, 3)

    def test_process_name_case_is_preserved(self):
        result = validate_ruleset_rules([{
            "process_name": ["ExampleApp", "exampleapp"],
        }], "process")

        self.assertEqual(result.issues, [])
        self.assertEqual(result.rules, [{
            "process_name": ["ExampleApp", "exampleapp"],
        }])


class NormalizationTests(unittest.TestCase):
    def test_exact_domain_and_keyword_normalizers_lowercase_values(self):
        self.assertEqual(normalize_domain(" Example.COM. "), "example.com")
        self.assertEqual(normalize_domain_keyword(" Google "), "google")

    def test_little_snitch_comments_are_removed_before_suffix_normalization(self):
        result = clean_denied_domains([
            "Example.com # noisy upstream comment / metadata",
        ])

        self.assertEqual(result, {
            "domain": ["example.com"],
            "domain_suffix": ["example.com"],
        })

    def test_suffix_normalizer_uses_root_and_subdomains_form(self):
        self.assertEqual(normalize_domain_suffix("example.com"), "example.com")
        self.assertEqual(normalize_domain_suffix(".Example.com"), "example.com")
        self.assertEqual(normalize_domain_suffix("+.example.com"), "example.com")

    def test_suffix_trie_removes_covered_suffixes(self):
        result = filter_domain_suffixes_with_trie({
            ".example.com",
            "+.example.com",
            "api.example.com",
        })
        self.assertEqual(result, {"example.com"})

    def test_suffix_removes_redundant_root_and_subdomain_exact_rules(self):
        rules = deduplicate_json([
            {"domain": ["example.com", "api.example.com", "keep.test"]},
            {"domain_suffix": [".example.com"]},
        ])
        values = {key: value for rule in rules for key, value in rule.items()}

        self.assertEqual(values["domain"], ["keep.test"])
        self.assertEqual(values["domain_suffix"], ["example.com"])

    def test_exact_dedup_keeps_entries_covered_by_a_suffix(self):
        rules = deduplicate_exact_rules([
            {"domain": ["example.com", "api.example.com"]},
            {"domain_suffix": ["example.com"]},
        ])
        values = {key: value for rule in rules for key, value in rule.items()}

        self.assertEqual(values["domain"], ["api.example.com", "example.com"])
        self.assertEqual(values["domain_suffix"], ["example.com"])

    def test_destination_domain_fields_are_packed_into_one_rule(self):
        rules = deduplicate_json([
            {"domain": ["exact.test"]},
            {"domain_suffix": ["suffix.test"]},
            {"domain_keyword": ["keyword"]},
            {"domain_regex": [r"^regex\\.test$"]},
            {"ip_cidr": ["192.0.2.1/24"]},
        ])

        self.assertEqual(rules, [
            {
                "domain": ["exact.test"],
                "domain_suffix": ["suffix.test"],
                "domain_keyword": ["keyword"],
                "domain_regex": [r"^regex\\.test$"],
            },
            {"ip_cidr": ["192.0.2.0/24"]},
        ])

    def test_destination_domain_packing_preserves_match_results(self):
        original = [
            {"domain": ["exact.test", "api.suffix.test"]},
            {"domain_suffix": ["suffix.test"]},
            {"domain_keyword": ["keyword"]},
            {"domain_regex": [r"^regex\d+\.test$"]},
        ]
        optimized = deduplicate_json(original)

        for domain in (
            "exact.test",
            "suffix.test",
            "deep.suffix.test",
            "contains-keyword.example",
            "regex42.test",
            "unrelated.test",
        ):
            self.assertEqual(
                matches_destination_domain(original, domain),
                matches_destination_domain(optimized, domain),
                domain,
            )

    def test_mihomo_classical_rules_put_regex_last(self):
        with tempfile.TemporaryDirectory() as directory:
            input_directory = os.path.join(directory, "singbox")
            output_directory = os.path.join(directory, "clash")
            os.makedirs(input_directory)
            with open(
                os.path.join(input_directory, "geosite-test.json"),
                "w",
                encoding="utf-8",
            ) as file:
                json.dump({
                    "version": 1,
                    "rules": [{
                        "domain": ["exact.test"],
                        "domain_suffix": ["suffix.test"],
                        "domain_keyword": ["keyword"],
                        "process_name": ["ExampleApp"],
                        "domain_regex": [r"^regex\.test$"],
                    }],
                }, file)

            with mock.patch(
                "proxy_ruleset_manager.utils.config.clash_output_directory",
                output_directory,
            ):
                convert_json_to_clash(input_directory)

            with open(
                os.path.join(output_directory, "geosite-test.yaml"),
                encoding="utf-8",
            ) as file:
                lines = [line.strip() for line in file if line.startswith("  - ")]

        self.assertEqual(lines, [
            "- DOMAIN,exact.test",
            "- DOMAIN-SUFFIX,suffix.test",
            "- DOMAIN-KEYWORD,keyword",
            "- PROCESS-NAME,ExampleApp",
            r"- DOMAIN-REGEX,^regex\.test$",
        ])

    def test_mihomo_suffix_output_is_root_and_subdomains_form(self):
        for value in ("example.com", ".example.com", "+.example.com"):
            self.assertEqual(clash_domain_rule("DOMAIN-SUFFIX", value), "+.example.com")

        with self.assertRaises(ValueError):
            clash_domain_rule("DOMAIN-SUFFIX", "*.example.com")

    def test_keyword_does_not_remove_domains_suffixes_or_narrower_keywords(self):
        rules, stats = deduplicate_json([
            {"domain_keyword": ["google", "googlevideo", "keep-keyword"]},
            {"domain": ["google.com", "api.google.com", "keep.example"]},
            {"domain_suffix": ["googleapis.com", "keep.test"]},
        ], return_stats=True)
        values = {key: value for rule in rules for key, value in rule.items()}

        self.assertEqual(values["domain_keyword"], ["google", "googlevideo", "keep-keyword"])
        self.assertEqual(values["domain"], ["api.google.com", "google.com", "keep.example"])
        self.assertEqual(values["domain_suffix"], ["googleapis.com", "keep.test"])
        self.assertEqual(stats["removed_entries"], 0)

    def test_deduplication_stats_separate_exact_and_coverage_removals(self):
        rules, stats = deduplicate_json([
            {"domain": ["Example.com", "example.com", "api.example.com"]},
            {"domain_suffix": ["example.com", "sub.example.com"]},
        ], return_stats=True)

        self.assertEqual(rules, [{"domain_suffix": ["example.com"]}])
        self.assertEqual(stats["input_entries"], 5)
        self.assertEqual(stats["output_entries"], 1)
        self.assertEqual(stats["exact_duplicates"], 1)
        self.assertEqual(stats["domain_covered_by_suffix"], 2)
        self.assertEqual(stats["suffix_covered_by_suffix"], 1)

    def test_invalid_cidr_is_not_returned(self):
        values = collapse_cidr_values(
            {"192.0.2.1/24", "192.0.2.128/25", "invalid"},
            "ip_cidr",
        )
        self.assertEqual(values, {"192.0.2.0/24"})

    def test_python_regex_does_not_remove_domain_rules(self):
        rules = deduplicate_json([
            {"domain": ["api.example.com"]},
            {"domain_suffix": ["static.example.com"]},
            {"domain_regex": [r"(^|\\.)example\\.com$"]},
        ])
        values = {key: value for rule in rules for key, value in rule.items()}

        self.assertEqual(values["domain"], ["api.example.com"])
        self.assertEqual(values["domain_suffix"], ["static.example.com"])


class ParserTests(unittest.TestCase):
    def test_list_parser_does_not_drop_ip_cidr6(self):
        dataframe = pd.DataFrame([
            {"pattern": "IP-CIDR6", "address": "2001:db8::/32", "other": None},
        ])
        parser = RuleParser()

        with mock.patch(
            "proxy_ruleset_manager.pipeline.parse_and_convert_to_dataframe",
            return_value=(dataframe, []),
        ):
            result = parser.parse_link_file_to_json("https://example.test/rules.yaml")

        self.assertEqual(result["rules"], [{"ip_cidr": ["2001:db8::/32"]}])

    def test_failed_required_source_does_not_write_partial_output(self):
        parser = RuleParser()
        valid = {"version": 1, "rules": [{"domain": ["example.com"]}]}

        def parse_link(link):
            return valid if link.endswith("good.json") else None

        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "geosite-test.json")
            with mock.patch.object(parser, "parse_link_file_to_json", side_effect=parse_link):
                stats = parser.generate_json_file(
                    ["https://example.test/good.json", "https://example.test/bad.json"],
                    output,
                    "test",
                    type="geosite",
                )

            self.assertFalse(stats["generated"])
            self.assertEqual(stats["failed_source_count"], 1)
            self.assertFalse(os.path.exists(output))

    def test_unsupported_rule_prevents_ruleset_publication(self):
        parser = RuleParser()
        unsupported = {
            "version": 1,
            "rules": [{"domain_suffix": ["example.com"], "network": ["udp"]}],
        }

        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "geosite-test.json")
            with mock.patch.object(parser, "parse_link_file_to_json", return_value=unsupported):
                stats = parser.generate_json_file(
                    ["https://example.test/rules.json"],
                    output,
                    "test",
                    type="geosite",
                )

            self.assertFalse(stats["generated"])
            self.assertEqual(stats["unsupported_count"], 1)
            self.assertFalse(os.path.exists(output))

    def test_invalid_suffix_prevents_ruleset_publication(self):
        parser = RuleParser()
        upstream = {
            "version": 1,
            "rules": [{"domain_suffix": ["example.com", "*.example.net"]}],
        }

        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "geosite-test.json")
            with mock.patch.object(parser, "parse_link_file_to_json", return_value=upstream):
                stats = parser.generate_json_file(
                    ["https://example.test/rules.json"],
                    output,
                    "test",
                    type="geosite",
                )

            self.assertFalse(stats["generated"])
            self.assertGreaterEqual(stats["invalid_count"], 1)
            self.assertFalse(os.path.exists(output))

    def test_single_upstream_removes_domains_covered_by_suffix(self):
        parser = RuleParser()
        upstream = {
            "version": 1,
            "rules": [
                {"domain": ["example.com", "api.example.com", "keep.test"]},
                {"domain_suffix": [".example.com"]},
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "geosite-test.json")
            with mock.patch.object(parser, "parse_link_file_to_json", return_value=upstream):
                stats = parser.generate_json_file(
                    ["https://example.test/rules.json"],
                    output,
                    "test",
                    type="geosite",
                )
            parser.optimize_output_rulesets(directory)

            with open(output, encoding="utf-8") as file:
                generated = json.load(file)

        self.assertTrue(stats["generated"])
        self.assertEqual(generated["rules"], [{
            "domain": ["keep.test"],
            "domain_suffix": ["example.com"],
        }])
        report = parser.quality_reports[-1]
        self.assertEqual(report["source_count"], 1)
        self.assertEqual(len(report["sources"]), 1)
        self.assertIn("merge_deduplication", report)


class QualityReportTests(unittest.TestCase):
    def test_semantic_overlap_uses_suffix_and_cidr_coverage(self):
        candidate = [
            {"domain": ["api.example.com"], "domain_suffix": ["sub.example.com"]},
            {"ip_cidr": ["192.0.2.128/25"]},
            {"domain_keyword": ["download"]},
        ]
        reference = [
            {"domain_suffix": ["example.com"]},
            {"ip_cidr": ["192.0.2.0/24"]},
            {"domain_keyword": ["down"]},
        ]

        summary = summarize_semantic_overlap(candidate, reference)

        self.assertEqual(summary["entries"], 4)
        self.assertEqual(summary["covered"], 3)
        self.assertEqual(summary["by_field"]["domain_keyword"]["covered"], 0)

    def test_light_candidate_analysis_builds_greedy_coverage_order(self):
        records = [
            {
                "url": "broad-source",
                "rules": [{"domain_suffix": ["example.com"]}],
            },
            {
                "url": "focused-source",
                "rules": [{"domain": ["api.example.com", "unique.test"]}],
                "correction_removed_entries": 1,
            },
        ]
        target = [{
            "domain": ["api.example.com", "unique.test"],
            "domain_suffix": ["example.com"],
        }]
        conflicts = {
            "download_strict": [{"domain": ["unique.test"]}],
        }

        analysis = analyze_light_source_candidates(records, target, conflicts)

        self.assertEqual(analysis["greedy_coverage_order"][0]["url"], "broad-source")
        self.assertEqual(
            analysis["greedy_coverage_order"][-1]["cumulative_target_coverage_ratio"],
            1.0,
        )
        focused = next(
            item for item in analysis["sources"]
            if item["url"] == "focused-source"
        )
        self.assertEqual(focused["correction_removed_entries"], 1)
        self.assertEqual(
            focused["classification_conflicts"]["download_strict"][
                "covered_source_entries"
            ],
            1,
        )
        self.assertEqual(
            analysis["non_bulk_scenario"]["maximum_source_entries"],
            10000,
        )

    def test_exact_provenance_reports_shared_entries_and_source_contribution(self):
        records = [
            {
                "url": "source-a",
                "rules": [
                    {"domain": ["shared.example", "only-a.example"]},
                ],
            },
            {
                "url": "source-b",
                "rules": [
                    {"domain": ["shared.example", "only-b.example"]},
                ],
            },
        ]
        final_rules = [{
            "domain": ["shared.example", "only-a.example", "only-b.example"],
        }]

        summary = summarize_provenance(
            build_provenance(records),
            final_rules,
            ["source-a", "source-b"],
        )

        self.assertEqual(summary["published_entries_with_multiple_exact_sources"], 1)
        self.assertEqual(summary["normalized_entries_shared_by_sources"], 1)
        self.assertEqual(summary["source_output_contribution"], {
            "source-a": 2,
            "source-b": 2,
        })
        self.assertEqual(summary["source_pair_overlaps"], [{
            "sources": ["source-a", "source-b"],
            "entry_count": 1,
        }])

    def test_quality_report_is_written_with_published_inventory(self):
        parser = RuleParser()
        parser.quality_reports = [{
            "ruleset": "geosite-test",
            "type": "geosite",
            "source_count": 1,
            "sources": [],
            "merge_deduplication": {},
            "output_entries_by_field": {"domain": 1},
            "provenance": {},
        }]

        with tempfile.TemporaryDirectory() as directory:
            output_directory = os.path.join(directory, "singbox")
            os.makedirs(output_directory)
            output = os.path.join(output_directory, "geosite-test.json")
            with open(output, "w", encoding="utf-8") as file:
                json.dump({"version": 1, "rules": [{"domain": ["example.com"]}]}, file)
            report_file = os.path.join(directory, "report", "ruleset-quality.json")

            parser.write_quality_report(output_directory, report_file)

            with open(report_file, encoding="utf-8") as file:
                report = json.load(file)

        self.assertEqual(report["published_inventory"], [{
            "ruleset": "geosite-test",
            "entries": 1,
            "entries_by_field": {"domain": 1},
        }])

    def test_multiple_upstreams_share_suffix_coverage_deduplication(self):
        parser = RuleParser()
        upstreams = {
            "https://example.test/one.json": {
                "version": 1,
                "rules": [{"domain_suffix": [".example.com"]}],
            },
            "https://example.test/two.json": {
                "version": 1,
                "rules": [
                    {"domain": ["api.example.com", "keep.test"]},
                    {"domain_suffix": ["sub.example.com"]},
                ],
            },
        }

        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "geosite-test.json")
            with mock.patch.object(
                parser,
                "parse_link_file_to_json",
                side_effect=lambda link: upstreams[link],
            ):
                stats = parser.generate_json_file(
                    list(upstreams),
                    output,
                    "test",
                    type="geosite",
                )
            parser.optimize_output_rulesets(directory)
            with open(output, encoding="utf-8") as file:
                generated = json.load(file)

        self.assertTrue(stats["generated"])
        self.assertEqual(generated["rules"], [{
            "domain": ["keep.test"],
            "domain_suffix": ["example.com"],
        }])
        report = parser.quality_reports[-1]
        self.assertEqual(report["source_count"], 2)
        self.assertEqual(len(report["sources"]), 2)
        self.assertEqual(parser.source_records_by_ruleset, {})


class ClassificationCorrectionTests(unittest.TestCase):
    def test_named_variant_inherits_base_classification_correction(self):
        parser = RuleParser()
        with tempfile.TemporaryDirectory() as directory:
            output_directory = os.path.join(directory, "output")
            corrections_directory = os.path.join(directory, "corrections")
            os.makedirs(output_directory)
            os.makedirs(corrections_directory)
            with open(
                os.path.join(output_directory, "geosite-category-direct@light.json"),
                "w",
                encoding="utf-8",
            ) as file:
                json.dump({
                    "version": 1,
                    "rules": [{"domain_suffix": ["googleapis.com", "keep.test"]}],
                }, file)
            with open(
                os.path.join(corrections_directory, "geosite-category-direct.json"),
                "w",
                encoding="utf-8",
            ) as file:
                json.dump({
                    "version": 1,
                    "rules": [{"domain_suffix": ["googleapis.com"]}],
                }, file)

            parser.apply_corrections_to_output(
                output_directory,
                corrections_directory,
            )
            with open(
                os.path.join(output_directory, "geosite-category-direct@light.json"),
                encoding="utf-8",
            ) as file:
                corrected = json.load(file)

        self.assertEqual(corrected["rules"], [{"domain_suffix": ["keep.test"]}])

    def test_correction_runs_before_suffix_coverage_pruning(self):
        parser = RuleParser()
        ruleset = {
            "version": 1,
            "rules": deduplicate_exact_rules([
                {"domain": ["api.example.com"]},
                {"domain_suffix": ["example.com"]},
            ]),
        }
        corrections = {
            "version": 1,
            # An exact correction removes the erroneous parent suffix itself,
            # but must not remove a valid child domain.
            "rules": [{"domain": ["example.com"]}],
        }

        corrected, _, removed_suffixes = parser.apply_corrections(
            ruleset,
            corrections,
        )
        optimized = deduplicate_json(corrected["rules"])

        self.assertEqual(removed_suffixes, 1)
        self.assertEqual(optimized, [{"domain": ["api.example.com"]}])

    def test_corrections_remove_misclassified_domains(self):
        parser = RuleParser()
        ruleset = {
            "version": 1,
            "rules": [
                {"domain": ["xmac.app", "foo.gstatic.com", "keep.example"]},
                {"domain_suffix": ["googleapis.com", "keep.example"]},
            ],
        }
        corrections = {
            "version": 1,
            "rules": [
                {"domain": ["xmac.app"]},
                {"domain_suffix": ["gstatic.com", "googleapis.com"]},
            ],
        }

        corrected, removed_domains, removed_suffixes = parser.apply_corrections(
            ruleset,
            corrections,
        )

        self.assertEqual(removed_domains, 2)
        self.assertEqual(removed_suffixes, 1)
        self.assertEqual(corrected["rules"], [
            {"domain": ["keep.example"]},
            {"domain_suffix": ["keep.example"]},
        ])

    def test_empty_corrections_have_a_stable_return_shape(self):
        parser = RuleParser()
        ruleset = {"version": 1, "rules": [{"domain": ["example.com"]}]}

        corrected, removed_domains, removed_suffixes = parser.apply_corrections(
            ruleset,
            {"version": 1, "rules": []},
        )

        self.assertEqual(corrected, ruleset)
        self.assertEqual((removed_domains, removed_suffixes), (0, 0))

    def test_suffix_correction_removes_more_specific_suffixes(self):
        parser = RuleParser()
        ruleset = {
            "version": 1,
            "rules": [{"domain_suffix": ["api.example.com", "keep.test"]}],
        }
        corrections = {
            "version": 1,
            "rules": [{"domain_suffix": [".example.com"]}],
        }

        corrected, removed_domains, removed_suffixes = parser.apply_corrections(
            ruleset,
            corrections,
        )

        self.assertEqual((removed_domains, removed_suffixes), (0, 1))
        self.assertEqual(corrected["rules"], [{"domain_suffix": ["keep.test"]}])


if __name__ == "__main__":
    unittest.main()
