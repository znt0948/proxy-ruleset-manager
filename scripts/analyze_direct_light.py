#!/usr/bin/env python3
"""Run the expensive direct@light source analysis on demand.

This script is intentionally separate from the normal ruleset build.  It only
downloads the direct ruleset and the rule families used as classification
conflict references, then writes a standalone local report.
"""

import argparse
import json
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from proxy_ruleset_manager.pipeline import RuleParser  # noqa: E402


REFERENCE_UPSTREAMS = [
    "category-direct.yaml",
    "category-download@!cn.yaml",
    "category-proxy.yaml",
    "geolocation-!cn.yaml",
    "category-vpn@!cn.yaml",
    "blocker-trash.yaml",
]


def main():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "report" / "direct-light-analysis.json",
    )
    args = argument_parser.parse_args()

    parser = RuleParser(capture_source_records=True)
    with tempfile.TemporaryDirectory(prefix="prm-direct-light-") as directory:
        for filename in REFERENCE_UPSTREAMS:
            succeeded = parser.parse_yaml_file(
                ROOT / "upstream" / filename,
                directory,
            )
            if not succeeded:
                raise RuntimeError(f"required analysis input failed: {filename}")

        parser.apply_corrections_to_output(
            directory,
            corrections_directory=ROOT / "corrections",
        )
        parser.optimize_output_rulesets(directory)
        analysis = parser.build_direct_light_analysis(
            directory,
            corrections_directory=ROOT / "corrections",
        )
        if analysis is None:
            raise RuntimeError("direct analysis could not be built")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = args.output.with_name(f".{args.output.name}.tmp")
    with temporary_output.open("w", encoding="utf-8") as file:
        json.dump(analysis, file, ensure_ascii=False, indent=2)
        file.write("\n")
    temporary_output.replace(args.output)
    print(args.output)


if __name__ == "__main__":
    main()
