import json
import os
import tempfile
import unittest

from proxy_ruleset_manager.exclusive import make_exclusive, verify_exclusive


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
        self.assertIn(("dnsapi.cn", "geosite-blocker-httpdns.json"), carved)
        self.assertIn(("119.29.29.29/32", "geoip-category-direct@light.json"), carved)

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
        direct = read(self.output, "geosite-category-direct@light.json")
        self.assertIn({"domain_suffix": ["cn.download.nvidia.com"]}, direct)

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
        self.assertIn(("domain_regex", "(^|\\.)tracking\\..*\\.miui\\.com$"), blocked)
        carved = {(c["value"], c["carved_from"]) for c in report["carved"]}
        self.assertIn(("dnsapi.cn", "geosite-blocker-httpdns.json"), carved)
        ties = {(t["value"], t["kept_in"]) for t in report["ties"]}
        self.assertIn(("kept-ads.example", "geosite-category-direct@light.json"), ties)

    def test_idempotent(self):
        make_exclusive(self.output, root=self.root)
        before = {name: read(self.output, name) for name in os.listdir(self.output)}
        report = make_exclusive(self.output, root=self.root)
        self.assertEqual(report["remaining"], [])
        self.assertEqual(before, {name: read(self.output, name) for name in os.listdir(self.output)})


if __name__ == "__main__":
    unittest.main()
