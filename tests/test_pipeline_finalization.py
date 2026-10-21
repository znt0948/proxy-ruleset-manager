import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import proxy_ruleset_manager.pipeline as pipeline_module
from proxy_ruleset_manager import exclusive
from proxy_ruleset_manager.pipeline import RuleParser


OUTPUT_FILES = {
    "geosite-blocker-trash@mobile.json": [
        {"domain_suffix": ["reject.example"]},
    ],
    "geosite-category-download@!cn.json": [
        {
            # The exact entry is deliberately redundant with nvidia.com.  It
            # must be pruned before make_exclusive, or the download tie wins.
            "domain": ["cn.download.nvidia.com"],
            "domain_suffix": [
                "nvidia.com",
                "icloud-content.com",
                "removed.example",
            ],
            "domain_keyword": ["excluded"],
            "domain_regex": [
                r"^excluded\.",
                r"^regex-excluded\.example$",
            ],
        },
    ],
    "geosite-filter-downloadKeywords@!cn.json": [
        {
            "domain_keyword": ["download"],
            "domain_regex": [r"^p[0-9]+-content\.icloud\.com$"],
        },
    ],
    "geosite-category-direct@light.json": [
        {
            "domain": ["cn.download.nvidia.com"],
            "domain_suffix": ["overlap.example"],
        },
    ],
}

CATEGORY_CORRECTION = {
    "version": 1,
    "rules": [{"domain_suffix": ["removed.example"]}],
    "exclude": [{
        "domain": [
            "gateway-asset.icloud-content.com",
            "excluded.overlap.example",
            "regex-excluded.example",
        ],
    }],
}

KEYWORD_CORRECTION = {
    "version": 1,
    "rules": [{
        "domain_regex": [r"^p[0-9]+-content\.icloud\.com$"],
    }],
}

PROBES = [
    "cn.download.nvidia.com",
    "nvidia.com",
    "gateway-asset.icloud-content.com",
    "edge.icloud-content.com",
    "cvws.icloud-content.com",
    "other.icloud-content.com",
    "icloud-content.com",
    "p1-content.icloud.com",
    "p200-content.icloud.com",
    "download.removed.example",
    "plain.removed.example",
    "excluded.overlap.example",
    "regex-excluded.example",
    "reject.example",
]


class ProductionFinalizationTests(unittest.TestCase):
    """Exercise the same post-parse method used by generate_singbox_rules."""

    @staticmethod
    def _write(path, document):
        with open(path, "w", encoding="utf-8") as file:
            json.dump(document, file, ensure_ascii=False, indent=2)

    def _make_fixture(self, directory, malformed_exclude=False):
        output = os.path.join(directory, "output")
        corrections = os.path.join(directory, "corrections")
        os.makedirs(output)
        os.makedirs(corrections)

        for filename, rules in OUTPUT_FILES.items():
            self._write(os.path.join(output, filename), {
                "version": 1,
                "rules": rules,
            })

        category_correction = dict(CATEGORY_CORRECTION)
        if malformed_exclude:
            category_correction["exclude"] = ["not an object"]
        self._write(
            os.path.join(corrections, "geosite-category-download.json"),
            category_correction,
        )
        self._write(
            os.path.join(corrections, "geosite-filter-downloadKeywords.json"),
            KEYWORD_CORRECTION,
        )
        return output, corrections

    @staticmethod
    def _matched_groups(output, hostname):
        groups = set()
        for group in exclusive.GROUPS:
            for filename in group["files"]:
                path = os.path.join(output, filename)
                if not os.path.exists(path):
                    continue
                with open(path, encoding="utf-8") as file:
                    rules = json.load(file).get("rules", [])
                if any(
                    exclusive._rule_matches(rule, name=hostname)
                    for rule in rules
                    if isinstance(rule, dict)
                ):
                    groups.add(group["name"])
        return groups

    @staticmethod
    def _rules(path):
        with open(path, encoding="utf-8") as file:
            return json.load(file).get("rules", [])

    def _finalize(self, parser, directory, compile_rules=False):
        output, corrections = self._make_fixture(directory)
        parser.finalize_singbox_rules(
            output,
            corrections_directory=corrections,
            root=directory,
            report_file=os.path.join(directory, "exclusive.json"),
            pre_directory=os.path.join(directory, "pre-exclusive"),
            compile_rules=compile_rules,
        )
        return output

    def test_fixture_membership_uses_production_finalization(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self._finalize(
                RuleParser(),
                directory,
                compile_rules=shutil.which("sing-box") is not None,
            )

            # The redundant download exact is pruned before exclusivity: the
            # direct exact wins over the remaining nvidia.com suffix.
            self.assertEqual(
                self._matched_groups(output, "cn.download.nvidia.com"),
                {"direct"},
            )
            self.assertEqual(
                self._matched_groups(output, "nvidia.com"),
                {"download"},
            )

            # The exact carve-out shrinks only the kept download suffix.
            self.assertEqual(
                self._matched_groups(output, "gateway-asset.icloud-content.com"),
                set(),
            )
            for hostname in (
                "edge.icloud-content.com",
                "cvws.icloud-content.com",
                "other.icloud-content.com",
                "icloud-content.com",
            ):
                self.assertEqual(self._matched_groups(output, hostname), {"download"})

            # Removing the p-number regex does not remove the separate
            # icloud-content.com suffix, and pN-content.icloud.com is not a
            # subdomain of that suffix.
            for hostname in ("p1-content.icloud.com", "p200-content.icloud.com"):
                self.assertEqual(self._matched_groups(output, hostname), set())

            # A removed suffix does not suppress an independent broad keyword.
            self.assertEqual(
                self._matched_groups(output, "plain.removed.example"),
                set(),
            )
            self.assertEqual(
                self._matched_groups(output, "download.removed.example"),
                {"download"},
            )

            # An excluded name covered by a direct suffix remains direct; an
            # excluded name covered only by the download regex/keyword falls
            # through to the default route.
            self.assertEqual(
                self._matched_groups(output, "excluded.overlap.example"),
                {"direct"},
            )
            self.assertEqual(
                self._matched_groups(output, "regex-excluded.example"),
                set(),
            )
            self.assertEqual(
                self._matched_groups(output, "reject.example"),
                {"reject"},
            )
            self.assertEqual(exclusive.verify_exclusive(output), [])

    def test_finalization_order_is_explicitly_guarded(self):
        events = []
        parser = RuleParser()

        for method_name in (
            "apply_corrections_to_output",
            "optimize_output_rulesets",
            "apply_final_exclusions_to_output",
        ):
            original = getattr(parser, method_name)

            def record(*args, _name=method_name, _original=original, **kwargs):
                events.append(_name)
                return _original(*args, **kwargs)

            setattr(parser, method_name, record)

        real_make_exclusive = pipeline_module.make_exclusive
        real_verify_exclusive = pipeline_module.verify_exclusive

        def record_make(*args, **kwargs):
            events.append("make_exclusive")
            return real_make_exclusive(*args, **kwargs)

        def record_verify(*args, **kwargs):
            events.append("verify_exclusive")
            return real_verify_exclusive(*args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                pipeline_module, "make_exclusive", side_effect=record_make
            ), mock.patch.object(
                pipeline_module, "verify_exclusive", side_effect=record_verify
            ):
                self._finalize(parser, directory)

        self.assertEqual(events, [
            "apply_corrections_to_output",
            "optimize_output_rulesets",
            "make_exclusive",
            "apply_final_exclusions_to_output",
            "verify_exclusive",
        ])

    def test_old_pre_exclusive_order_is_rejected_by_this_fixture(self):
        """The historical mutant keeps cn in download and fails the contract."""
        with tempfile.TemporaryDirectory() as directory:
            output, corrections = self._make_fixture(directory)
            parser = RuleParser()
            parser.apply_corrections_to_output(output, corrections)
            # This is intentionally the old, wrong order.  It is a local
            # mutation witness only; production calls finalize_singbox_rules.
            parser.apply_final_exclusions_to_output(output, corrections)
            parser.optimize_output_rulesets(output)
            report = pipeline_module.make_exclusive(output, root=directory)
            self.assertEqual((report["remaining"], report["orphaned"]), ([], []))
            self.assertEqual(
                self._matched_groups(output, "cn.download.nvidia.com"),
                {"download"},
            )
            self.assertNotEqual(
                self._matched_groups(output, "cn.download.nvidia.com"),
                {"direct"},
            )

    def test_malformed_exclude_fails_finalization(self):
        parser = RuleParser()
        with tempfile.TemporaryDirectory() as directory:
            output, corrections = self._make_fixture(
                directory,
                malformed_exclude=True,
            )
            with self.assertRaises(ValueError):
                parser.finalize_singbox_rules(
                    output,
                    corrections_directory=corrections,
                    root=directory,
                    compile_rules=False,
                )

    def test_report_classifies_correction_and_exclude_orphans_as_intentional(self):
        parser = RuleParser()
        with tempfile.TemporaryDirectory() as directory:
            report_path = os.path.join(directory, "exclusive.json")
            output = self._finalize(parser, directory)
            with open(report_path, encoding="utf-8") as file:
                report = json.load(file)

            intentional = {
                item["name"]: item["reason"]
                for item in report["intentional_orphaned"]
            }
            self.assertEqual(report["orphaned"], [])
            self.assertEqual(intentional["removed.example"], "correction")
            self.assertEqual(
                intentional["gateway-asset.icloud-content.com"],
                "exclude",
            )

    def test_report_does_not_hide_an_accidental_orphan(self):
        parser = RuleParser()
        documents = [
            (
                "direct",
                "geosite-category-direct@light.json",
                [{"domain": ["lost.example"]}],
            ),
        ]
        report = {"changed": [], "orphaned": []}
        parser._classify_final_exclusive_changes(
            report,
            documents,
            documents,
            documents,
            documents,
            [],
            set(),
        )
        self.assertEqual(report["intentional_orphaned"], [])
        self.assertEqual(report["orphaned"][0]["name"], "lost.example")
        self.assertEqual(report["orphaned"][0]["reason"], "exclusivity")

    @unittest.skipUnless(
        shutil.which("sing-box") and os.path.exists(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "tools",
                "srmatch",
                "srmatch",
            )
        ),
        "sing-box and tools/srmatch are not installed",
    )
    def test_compiled_fixture_matches_python_membership(self):
        srmatch = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "tools",
            "srmatch",
            "srmatch",
        )
        with tempfile.TemporaryDirectory() as directory:
            output = self._finalize(RuleParser(), directory, compile_rules=True)
            json_paths = [
                os.path.join(output, filename)
                for filename in OUTPUT_FILES
            ]
            srs_paths = [path[:-5] + ".srs" for path in json_paths]
            paths = json_paths + srs_paths
            result = subprocess.run(
                [srmatch, *paths],
                input="\n".join(PROBES) + "\n",
                capture_output=True,
                text=True,
                check=True,
            )
            matches = result.stdout.splitlines()
            self.assertEqual(len(matches), len(PROBES))
            count = len(json_paths)
            for hostname, line in zip(PROBES, matches):
                found = {int(index) for index in line.split(",") if index}
                expected = {
                    index
                    for index, path in enumerate(json_paths)
                    if any(
                        exclusive._rule_matches(rule, name=hostname)
                        for rule in self._rules(path)
                    )
                }
                self.assertEqual(found & set(range(count)), expected, hostname)
                self.assertEqual(
                    {index - count for index in found if index >= count},
                    expected,
                    hostname,
                )


if __name__ == "__main__":
    unittest.main()
