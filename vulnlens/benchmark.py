"""Deterministic synthetic regression benchmark for VulnLens rules.

Only scans bundled synthetic fixtures; never scans or transmits the user's repository.
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .cli import scan

FIXTURES = {
    "secret_assignment.py": 'API_KEY = "demo_not_a_real_secret_123456789"\n',
    "Dockerfile": "FROM python:3.12\nUSER root\nADD https://example.invalid/archive.tar.gz /tmp/a.tar.gz\n",
    ".github/workflows/demo.yml": "name: demo\njobs:\n  scan:\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo safe\npermissions: write-all\n",
}
EXPECTED = {"VL001", "VL101", "VL102", "VL201", "VL202"}

def run_benchmark() -> dict:
    with tempfile.TemporaryDirectory(prefix="vulnlens-benchmark-") as tmp:
        root = Path(tmp)
        for name, text in FIXTURES.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        report = scan(root)
        found = {item["rule"] for item in report["findings"]}
        return {
            "tool": "VulnLens benchmark",
            "fixture_type": "synthetic-only",
            "expected_rules": sorted(EXPECTED),
            "detected_rules": sorted(found),
            "missing_rules": sorted(EXPECTED - found),
            "unexpected_rules": sorted(found - EXPECTED),
            "passed": EXPECTED <= found,
            "finding_count": len(report["findings"]),
            "notice": "This smoke benchmark measures fixture detection only; it is not a measure of real-world precision or recall.",
        }

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", metavar="FILE", help="Write benchmark results as JSON")
    args = parser.parse_args(argv)
    result = run_benchmark()
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.json:
        Path(args.json).write_text(rendered + "\n", encoding="utf-8")
    return 0 if result["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
