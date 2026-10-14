"""Differential test: the published rule sets under sing-box's own matcher.

The exclusivity rewrite (exclusive.py) decides overlaps with a Python model
of sing-box's headless rule semantics. This test checks that model, and the
properties the rewrite promises, against the real engine — the srmatch tool
(tools/srmatch) links the sing-box version clients run:

1. fidelity: for every probe and rule set, the Python model and sing-box
   agree (JSON source files);
2. compiled: the .srs files clients download match exactly like their JSON
   sources (they are compiled by the build's sing-box, read by the
   clients');
3. exclusivity: under sing-box, no name or address is matched by rule sets
   of more than one destination;
4. order independence: the destination does not depend on the order of the
   client's route rules;
5. intended changes: with the rule sets from before the rewrite
   (build/pre-exclusive, written by the build), every name whose
   destination sing-box sees change is listed in report/exclusive.json with
   the same before/after, and no name loses every match.

Probes: the rewrite's own probes (every entry, keyword and regex regions),
boundary names (subdomains, parents and look-alikes of suffix and exact
entries), and the names the report lists. Real traffic names can be added
locally with HZ_REAL_NAMES=<file> (one name per line); the repository is
public, so such files are never committed.

The test is skipped when srmatch is missing, unless SRMATCH_REQUIRED=1 (CI).
"""
import ipaddress
import json
import os
import subprocess
import unittest

from proxy_ruleset_manager import exclusive

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULE_DIR = os.environ.get("RULE_DIR", os.path.join(ROOT, "rule", "singbox"))
PRE_DIR = os.environ.get("PRE_EXCLUSIVE_DIR", os.path.join(ROOT, "build", "pre-exclusive"))
REPORT = os.path.join(ROOT, "report", "exclusive.json")
SRMATCH = os.environ.get("SRMATCH", os.path.join(ROOT, "tools", "srmatch", "srmatch"))
REQUIRED = os.environ.get("SRMATCH_REQUIRED") == "1"
# Boundary names are sampled from the entries to keep the run short.
BOUNDARY_SAMPLE = 4000


def _files():
    return [(group["name"], filename) for group in exclusive.GROUPS for filename in group["files"]
            if os.path.exists(os.path.join(RULE_DIR, filename))]


def _srmatch(paths, probes):
    """Indexes of the rule sets matching each probe, per sing-box."""
    result = subprocess.run([SRMATCH, *paths], input="\n".join(probes) + "\n", capture_output=True, text=True, check=True)
    lines = result.stdout.split("\n")[:len(probes)]
    return [frozenset(int(i) for i in line.split(",") if i) for line in lines]


def _boundary(documents):
    """Subdomains, parents and look-alikes of suffix and exact entries."""
    names = set()
    for _, _, rules in documents:
        index = exclusive.RuleIndex(exclusive._flatten(rules))
        entries = sorted(index.entries())
        step = max(1, len(entries) // BOUNDARY_SAMPLE)
        for field, value in entries[::step]:
            value = value.lstrip(".")
            labels = value.split(".")
            names.add("a." + value)
            if len(labels) > 2:
                names.add(".".join(labels[1:]))
            if field == "domain_suffix":
                names.add("x" + value)  # look-alike: no label boundary
    return {name for name in names if exclusive.HOSTNAME.fullmatch(name)}


class SingBoxDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(SRMATCH):
            if REQUIRED:
                raise RuntimeError(f"srmatch not found at {SRMATCH}")
            raise unittest.SkipTest("srmatch not built (go build -o tools/srmatch/srmatch ./tools/srmatch)")
        cls.files = _files()
        cls.documents = exclusive._load_documents(RULE_DIR)
        probes = exclusive._probes(cls.documents)
        cls.names = sorted({p for kind, p in probes if kind == "name"} | _boundary(cls.documents))
        cls.addresses = sorted({str(p) for kind, p in probes if kind == "address"})
        with open(REPORT, encoding="utf-8") as file:
            cls.report = json.load(file)
        cls.names = sorted(set(cls.names) | {x["name"] for x in cls.report.get("changed", []) + cls.report.get("orphaned", [])})
        real = os.environ.get("HZ_REAL_NAMES")
        if real:
            with open(real, encoding="utf-8") as file:
                extra = {line.strip().lower().rstrip(".") for line in file if line.strip()}
            cls.names = sorted(set(cls.names) | {n for n in extra if exclusive.HOSTNAME.fullmatch(n)})
        cls.json_paths = [os.path.join(RULE_DIR, filename) for _, filename in cls.files]
        cls.srs_paths = [path[:-5] + ".srs" for path in cls.json_paths]
        cls.has_srs = all(os.path.exists(path) for path in cls.srs_paths)
        paths = cls.json_paths + (cls.srs_paths if cls.has_srs else [])
        cls.name_matches = _srmatch(paths, cls.names)
        cls.address_matches = _srmatch(paths, cls.addresses) if cls.addresses else []

    def test_model_agrees_with_singbox(self):
        """The Python model behind the rewrite matches like sing-box."""
        rules = {filename: [r for r in rules if isinstance(r, dict)] for _, filename, rules in self.documents}
        cache, mismatches = {}, []
        for kind, probes, matches in (("name", self.names, self.name_matches), ("address", self.addresses, self.address_matches)):
            for probe, found in zip(probes, matches):
                for i, (_, filename) in enumerate(self.files):
                    argument = {"name": probe} if kind == "name" else {"address": ipaddress.ip_address(probe)}
                    model = any(exclusive._rule_matches(rule, cache=cache, **argument) for rule in rules[filename])
                    if model != (i in found):
                        mismatches.append(f"{probe} {filename}: model {model}, sing-box {i in found}")
        self.assertEqual(mismatches[:20], [], f"{len(mismatches)} mismatches of {len(self.names) + len(self.addresses)} probes")

    def test_compiled_sets_match_sources(self):
        """The .srs files clients load match like their JSON sources."""
        if not self.has_srs:
            self.skipTest("no .srs files")
        count, differences = len(self.json_paths), []
        for probes, matches in ((self.names, self.name_matches), (self.addresses, self.address_matches)):
            for probe, found in zip(probes, matches):
                for i, (_, filename) in enumerate(self.files):
                    if (i in found) != (i + count in found):
                        differences.append(f"{probe} {filename}: json {i in found}, srs {i + count in found}")
        self.assertEqual(differences[:20], [], f"{len(differences)} differences")

    def test_destinations_are_exclusive(self):
        """No probe is matched by more than one destination."""
        overlaps = []
        for probes, matches in ((self.names, self.name_matches), (self.addresses, self.address_matches)):
            for probe, found in zip(probes, matches):
                groups = {self.files[i][0] for i in found if i < len(self.files)}
                if len(groups) > 1:
                    overlaps.append(f"{probe}: {sorted(groups)}")
        self.assertEqual(overlaps[:20], [], f"{len(overlaps)} overlaps")

    def test_order_does_not_matter(self):
        """The first matching set in client order, and in reverse, agree."""
        position = {filename: i for i, (_, filename) in enumerate(self.files)}
        order = [(group, filename) for group, filename in exclusive.CLIENT_ORDER if filename in position]

        def destination(found, sequence):
            for group, filename in sequence:
                if position[filename] in found:
                    return group
            return None

        differ = [name for name, found in zip(self.names, self.name_matches)
                  if destination(found, order) != destination(found, list(reversed(order)))]
        self.assertEqual(differ[:20], [], f"{len(differ)} names depend on rule order")

    def test_changes_are_the_reported_ones(self):
        """Destination changes from the rewrite, per sing-box, are the reported ones."""
        pre = [os.path.join(PRE_DIR, filename) for _, filename in self.files]
        if not all(os.path.exists(path) for path in pre):
            self.skipTest("no pre-exclusivity rule sets (written by the build to build/pre-exclusive)")
        before = _srmatch(pre, self.names)
        order = [(group, filename) for group, filename in exclusive.CLIENT_ORDER]
        position = {filename: i for i, (_, filename) in enumerate(self.files)}

        def destination(found):
            for group, filename in order:
                if filename in position and position[filename] in found:
                    return group
            return None

        reported = {x["name"]: (x["before"], x["after"]) for x in self.report.get("changed", [])}
        unexplained, orphaned = [], []
        for name, old, new in zip(self.names, before, self.name_matches):
            a, b = destination(old), destination(new)
            if a == b:
                continue
            if b is None:
                orphaned.append(f"{name}: {a} -> none")
            elif reported.get(name) != (a, b):
                unexplained.append(f"{name}: {a} -> {b} (report: {reported.get(name)})")
        self.assertEqual(orphaned[:20], [], f"{len(orphaned)} names lost every match")
        self.assertEqual(unexplained[:20], [], f"{len(unexplained)} unreported destination changes")


if __name__ == "__main__":
    unittest.main()
