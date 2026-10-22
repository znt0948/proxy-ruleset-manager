import json
import os
import tempfile
import unittest

import yaml

from proxy_ruleset_manager import exclusive
from proxy_ruleset_manager.contracts import validate_ruleset_rules
from proxy_ruleset_manager.pipeline import RuleParser


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SELF_HOST = os.path.join(ROOT, "self-host", "geosite-continuous@selfhost.json")
HOOK = os.path.join(ROOT, "upstream", "category-continuous.yaml")
OUTPUT_NAME = "geosite-category-continuous.json"


def read_json(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


class ContinuousLabelTests(unittest.TestCase):
    def test_hand_kept_source_is_a_strict_geosite_label_set(self):
        document = read_json(SELF_HOST)
        result = validate_ruleset_rules(document["rules"], "geosite")

        self.assertEqual(result.issues, [])
        self.assertEqual(
            sum(len(rule.get(field, [])) for rule in result.rules for field in (
                "domain", "domain_suffix"
            )),
            19,
        )
        domains = {
            value
            for rule in result.rules
            for field in ("domain", "domain_suffix")
            for value in rule.get(field, [])
        }
        self.assertEqual(
            sum(len(rule.get("domain", [])) for rule in result.rules),
            15,
        )
        self.assertEqual(
            sum(len(rule.get("domain_suffix", [])) for rule in result.rules),
            4,
        )
        for rejected in (
            "v16m.tiktokcdn-us.com",
            "v19.tiktokcdn-us.com",
            "v45.tiktokcdn-us.com",
            "video-s.twimg.com",
            "video.pscp.tv",
            "video.twimg.com",
            "bilivideo.cn",
            "bilivideo.com",
            "bilivideo.net",
        ):
            self.assertNotIn(rejected, domains)
        self.assertIn(
            "googlevideo.com",
            {value for rule in result.rules for value in rule.get("domain_suffix", [])},
        )
        self.assertNotIn("domain_keyword", document["rules"][0])
        self.assertNotIn("domain_regex", document["rules"][0])

    def test_build_hook_uses_the_hand_kept_local_source(self):
        with open(HOOK, encoding="utf-8") as file:
            hook = yaml.safe_load(file)
        self.assertEqual(hook, {
            "geosite": ["self-host/geosite-continuous@selfhost.json"],
        })

        parsed = RuleParser().parse_link_file_to_json(SELF_HOST)
        self.assertEqual(parsed["rules"], read_json(SELF_HOST)["rules"])

    def test_continuous_output_is_outside_exclusivity_groups(self):
        grouped_files = {
            filename
            for group in exclusive.GROUPS
            for filename in group["files"]
        }
        self.assertNotIn(OUTPUT_NAME, grouped_files)
        self.assertNotIn("continuous", {group["name"] for group in exclusive.GROUPS})

        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, OUTPUT_NAME)
            with open(output, "w", encoding="utf-8") as file:
                json.dump(read_json(SELF_HOST), file, indent=2)
                file.write("\n")
            with open(output, "rb") as file:
                before = file.read()

            report = exclusive.make_exclusive(directory, root=directory)

            with open(output, "rb") as file:
                after = file.read()
            self.assertEqual(report["remaining"], [])
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
