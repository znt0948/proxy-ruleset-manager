import json
import os
import tempfile
import unittest

from proxy_ruleset_manager.exclusive import GROUPS, _rule_matches, make_exclusive, verify_exclusive


def destinations(directory, name):
    """Destinations whose rule sets match name."""
    found = set()
    for group in GROUPS:
        for filename in group["files"]:
            path = os.path.join(directory, filename)
            if os.path.exists(path) and any(_rule_matches(rule, name=name) for rule in read(directory, filename)):
                found.add(group["name"])
    return found


def write(directory, name, rules):
    with open(os.path.join(directory, name), "w", encoding="utf-8") as file:
        json.dump({"version": 1, "rules": rules}, file)


def read(directory, name):
    with open(os.path.join(directory, name), encoding="utf-8") as file:
        return json.load(file)["rules"]


class ExclusiveTest(unittest.TestCase):
    def setUp(self):
        self.output = tempfile.mkdtemp()
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "self-host"))
        write(self.output, "geosite-blocker-httpdns.json", [{"domain": ["dns.weixin.qq.com"], "domain_keyword": ["dnsapi"]}])
        write(self.output, "geosite-category-download@!cn.json", [{"domain_suffix": ["download.nvidia.com", "both.example", "hand.example"], "domain": ["dl.google.com"]}])
        write(self.output, "geosite-category-direct@light.json", [{
            "domain_suffix": ["qq.com", "cn.download.nvidia.com", "both.example", "hand.example", "dnsapi.cn"],
            "domain": ["dl.google.com"]}])
        write(self.output, "geoip-blocker-httpdns.json", [{"ip_cidr": ["119.29.29.29/32"]}])
        write(self.output, "geoip-category-direct@light.json", [{"ip_cidr": ["119.28.0.0/15", "10.0.0.0/8"]}])
        write(self.root, "self-host/geosite-direct@selfhost.json", [{"domain_suffix": ["hand.example"]}])

    def test_destinations_do_not_overlap(self):
        report = make_exclusive(self.output, root=self.root)
        self.assertEqual(report["remaining"], [])
        self.assertEqual(verify_exclusive(self.output), [])
        ties = {(t["value"], t["kept_in"]) for t in report["ties"]}
        # Identical entries: hand-kept destination wins, else client order.
        self.assertIn(("hand.example", "geosite-category-direct@light.json"), ties)
        self.assertIn(("both.example", "geosite-category-download@!cn.json"), ties)
        self.assertIn(("dl.google.com", "geosite-category-download@!cn.json"), ties)
        carved = {(c["value"], c["carved_from"]) for c in report["carved"]}
        # More specific entries are carved out of broader ones.
        self.assertIn(("cn.download.nvidia.com", "geosite-category-download@!cn.json"), carved)
        self.assertIn(("dns.weixin.qq.com", "geosite-category-direct@light.json"), carved)
        self.assertIn(("119.29.29.29/32", "geoip-category-direct@light.json"), carved)
        self.assertEqual(destinations(self.output, "dnsapi.cn"), {"reject"})
        self.assertEqual(destinations(self.output, "api.dnsapi.cn"), {"reject"})

        direct = read(self.output, "geosite-category-direct@light.json")
        self.assertEqual(direct[0]["type"], "logical")
        inverted = direct[0]["rules"][1]
        self.assertTrue(inverted["invert"])
        self.assertEqual(inverted["domain"], ["dns.weixin.qq.com"])
        self.assertNotIn("both.example", direct[0]["rules"][0]["domain_suffix"])
        geoip = read(self.output, "geoip-category-direct@light.json")
        self.assertEqual(geoip[0]["rules"][1], {"ip_cidr": ["119.29.29.29/32"], "invert": True})

    def test_nested_entries_stay_matched(self):
        # download.nvidia.com is carved out of direct's nvidia.com, but
        # direct's own cn.download.nvidia.com must still match.
        write(self.output, "geosite-category-download@!cn.json", [{"domain_suffix": ["download.nvidia.com"]}])
        write(self.output, "geosite-category-direct@light.json", [{"domain_suffix": ["nvidia.com", "cn.download.nvidia.com"]}])
        report = make_exclusive(self.output, root=self.root)
        self.assertEqual(report["remaining"], [])
        self.assertEqual(destinations(self.output, "cn.download.nvidia.com"), {"direct"})
        self.assertEqual(destinations(self.output, "x.cn.download.nvidia.com"), {"direct"})
        self.assertEqual(destinations(self.output, "download.nvidia.com"), {"download"})
        self.assertEqual(destinations(self.output, "www.nvidia.com"), {"direct"})

    def test_blocking_wins_over_routing(self):
        # The direct list names google-analytics.com exactly, the block list
        # covers it as a suffix: it stays blocked (direct is no allowlist).
        # A keyword block and a hand-kept direct entry do not win.
        write(self.output, "adguard-blocker@mobile.json", [{"domain_suffix": ["google-analytics.com", "kept-ads.example"],
                                                            "domain_regex": ["(^|\\.)tracking\\..*\\.miui\\.com$"]}])
        write(self.output, "geosite-category-direct@light.json", [{
            "domain": ["google-analytics.com", "tracking.intl.miui.com"],
            "domain_suffix": ["dnsapi.cn", "kept-ads.example"]}])
        write(self.root, "self-host/geosite-direct@selfhost.json", [{"domain_suffix": ["kept-ads.example"]}])
        report = make_exclusive(self.output, root=self.root)
        self.assertEqual(report["remaining"], [])
        blocked = {(b["field"], b["value"]) for b in report["blocked"]}
        self.assertIn(("domain", "google-analytics.com"), blocked)
        self.assertIn(("domain_regex", r"(^|\.)tracking\..*\.miui\.com$"), blocked)
        self.assertEqual(destinations(self.output, "google-analytics.com"), {"reject"})
        self.assertEqual(destinations(self.output, "tracking.intl.miui.com"), {"reject"})
        self.assertEqual(destinations(self.output, "dnsapi.cn"), {"reject"})
        carved = {(c["value"], c["carved_from"]) for c in report["carved"]}
        ties = {(t["value"], t["kept_in"]) for t in report["ties"]}
        self.assertIn(("kept-ads.example", "geosite-category-direct@light.json"), ties)

    def test_keyword_and_regex_blocks_win_except_confirmed_exact_domain(self):
        write(self.output, "geosite-blocker-httpdns.json", [{
            "domain_keyword": ["api-dns", "api.dns", "dnsapi", "httpdns"],
            "domain_regex": [r"^regex\."],
        }])
        write(self.output, "geosite-category-direct@light.json", [{
            "domain_suffix": ["dnsapi.cn", "aliyuncs.com"],
        }])
        write(self.root, "self-host/geosite-direct@selfhost.json", [{
            "domain_suffix": ["aliyuncs.com"],
        }])
        write(self.root, "self-host/keyword-block-exceptions.json", [{
            "domain": ["dnsapi.cn", "unused.example"],
        }])
        report = make_exclusive(self.output, root=self.root)
        self.assertEqual((report["remaining"], report["orphaned"]), ([], []))
        self.assertEqual(destinations(self.output, "dnsapi.cn"), {"direct"})
        for hostname in (
            "api-dns.dnsapi.cn",
            "api.dnsapi.cn",
            "httpdns.dnsapi.cn",
            "regex.dnsapi.cn",
            "xhttpdnsx.aliyuncs.com",
            "httpdns-api.aliyuncs.com",
        ):
            self.assertEqual(destinations(self.output, hostname), {"reject"}, hostname)
        self.assertEqual(destinations(self.output, "oss-cn-hangzhou.aliyuncs.com"), {"direct"})
        self.assertEqual(destinations(self.output, "httpdns.example.com"), {"reject"})
        self.assertEqual(destinations(self.output, "regex.example.com"), {"reject"})
        self.assertEqual(destinations(self.output, "unused.example"), set())

    def test_hand_kept_route_beats_non_keyword_block(self):
        write(self.output, "adguard-blocker@mobile.json", [{
            "domain_suffix": ["suffix-block.example"],
        }])
        write(self.output, "geosite-category-direct@light.json", [{
            "domain": ["exact.suffix-block.example"],
            "domain_suffix": ["suffix-block.example"],
        }])
        write(self.root, "self-host/geosite-direct@selfhost.json", [{
            "domain": ["exact.suffix-block.example"],
            "domain_suffix": ["suffix-block.example"],
        }])
        report = make_exclusive(self.output, root=self.root)
        self.assertEqual((report["remaining"], report["orphaned"]), ([], []))
        self.assertEqual(destinations(self.output, "exact.suffix-block.example"), {"direct"})
        self.assertEqual(destinations(self.output, "x.suffix-block.example"), {"direct"})

    def test_specificity_beats_a_broader_hand_kept_route(self):
        # A direct exact entry remains more specific than a hand-kept
        # download suffix.  The B2 keyword precedence change must not alter
        # this existing direct-vs-download rule.
        write(self.output, "geosite-category-download@!cn.json", [{
            "domain_suffix": ["gofile.example"],
        }])
        write(self.output, "geosite-category-direct@light.json", [{
            "domain": ["gofile.example"],
        }])
        write(self.root, "self-host/geosite-direct@selfhost.json", [{
            "domain": ["gofile.example"],
        }])
        write(self.root, "self-host/geosite-download@selfhost.json", [{
            "domain_suffix": ["gofile.example"],
        }])
        report = make_exclusive(self.output, root=self.root)
        self.assertEqual((report["remaining"], report["orphaned"]), ([], []))
        self.assertEqual(destinations(self.output, "gofile.example"), {"direct"})
        self.assertEqual(destinations(self.output, "x.gofile.example"), {"download"})

    def test_exception_without_route_match_does_nothing(self):
        write(self.output, "geosite-blocker-httpdns.json", [{
            "domain_keyword": ["dnsapi"],
        }])
        write(self.output, "geosite-category-direct@light.json", [{
            "domain_suffix": ["unrelated.example"],
        }])
        write(self.root, "self-host/keyword-block-exceptions.json", [{
            "domain": ["dnsapi.cn"],
        }])
        report = make_exclusive(self.output, root=self.root)
        self.assertEqual((report["remaining"], report["orphaned"]), ([], []))
        self.assertEqual(destinations(self.output, "dnsapi.cn"), {"reject"})

    def test_keyword_suffix_probe_is_complete_not_a_stride_sample(self):
        suffixes = [f"s{number:03d}.example" for number in range(801)]
        target = "s001.example"
        old_stride = sorted(suffixes)[::max(1, len(suffixes) // 400)]
        self.assertNotIn(target, old_stride)
        write(self.output, "geosite-blocker-httpdns.json", [{"domain_keyword": ["needle"]}])
        write(self.output, "geosite-category-direct@light.json", [{"domain_suffix": suffixes}])

        report = make_exclusive(self.output, root=self.root)
        self.assertEqual((report["remaining"], report["orphaned"]), ([], []))
        regions = {
            (item["pattern"]["domain_keyword"], item["overlapping_entries"])
            for item in report["regions"]
            if "domain_keyword" in item.get("pattern", {})
        }
        self.assertIn(("needle", len(suffixes)), regions)
        self.assertEqual(destinations(self.output, f"xneedlex.{target}"), {"reject"})

    def test_no_orphans_when_a_tie_moves_an_entry(self):
        # direct's regex only has the literal tail ".cn", so it "overlaps"
        # download's nvidia.cn; the hand-kept tie moves nvidia.cn to direct.
        # Carving nvidia.cn out of direct for the regex would orphan it.
        write(self.output, "geosite-category-download@!cn.json", [{"domain_suffix": ["nvidia.cn", "download.nvidia.com"]}])
        write(self.output, "geosite-category-direct@light.json", [{"domain_suffix": ["nvidia.cn", "qq.com"],
                                                                   "domain_regex": [".+\\.awsdns-cn-[0-9][a-e0-9]\\.cn$"]}])
        write(self.root, "self-host/geosite-direct@selfhost.json", [{"domain_suffix": ["nvidia.cn"]}])
        report = make_exclusive(self.output, root=self.root)
        self.assertEqual((report["remaining"], report["orphaned"]), ([], []))
        self.assertEqual(destinations(self.output, "nvidia.cn"), {"direct"})
        self.assertEqual(destinations(self.output, "www.nvidia.cn"), {"direct"})

    def test_idempotent(self):
        make_exclusive(self.output, root=self.root)
        before = {name: read(self.output, name) for name in os.listdir(self.output)}
        report = make_exclusive(self.output, root=self.root)
        self.assertEqual(report["remaining"], [])
        self.assertEqual(before, {name: read(self.output, name) for name in os.listdir(self.output)})


if __name__ == "__main__":
    unittest.main()
