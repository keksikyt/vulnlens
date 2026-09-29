import tempfile
import unittest
from pathlib import Path

from vulnlens.cli import apply_baseline, scan, to_sarif, write_baseline
from vulnlens.deps import parse_requirements
from vulnlens.html_report import render_html


class ScannerTests(unittest.TestCase):
    def test_secret_is_detected_but_value_is_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "app.py").write_text('API_KEY = "thisIsARealisticSecret12345"\n')
            report = scan(root)
            self.assertEqual(report["summary"]["total"], 1)
            self.assertNotIn("thisIsARealisticSecret12345", str(report))

    def test_docker_root_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "Dockerfile").write_text("FROM python:3.12\nUSER root\n")
            self.assertTrue(any(x["rule"] == "VL101" for x in scan(root)["findings"]))

    def test_empty_tree(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(scan(Path(d))["summary"]["total"], 0)

    def test_sarif_format(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "Dockerfile").write_text("FROM alpine\nUSER root\n")
            sarif = to_sarif(scan(root))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "VulnLens")
            self.assertTrue(sarif["runs"][0]["results"])

    def test_baseline_suppresses_existing_finding(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "Dockerfile").write_text("FROM alpine\nUSER root\n")
            report = scan(root)
            baseline = root / "baseline.json"
            write_baseline(report, baseline)
            apply_baseline(report, baseline)
            self.assertEqual(report["summary"]["suppressed"], len(report["findings"]))
            self.assertEqual(report["summary"]["new"], 0)

    def test_baseline_detects_new_finding(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            docker = root / "Dockerfile"
            docker.write_text("FROM alpine\nUSER root\n")
            baseline = root / "baseline.json"
            write_baseline(scan(root), baseline)
            docker.write_text("FROM alpine\nUSER root\nADD https://example.invalid/file /tmp/file\n")
            report = scan(root)
            apply_baseline(report, baseline)
            self.assertGreater(report["summary"]["new"], 0)

    def test_html_report_escapes_untrusted_finding_text(self):
        report = {
            "version": "test",
            "target": "<script>alert(1)</script>",
            "summary": {"by_severity": {"high": 1}},
            "notice": "notice",
            "findings": [{
                "severity": "high", "rule": "VL001", "file": "<img src=x>",
                "line": 1, "message": "<script>bad</script>", "remediation": "&"
            }],
        }
        html = render_html(report)
        self.assertNotIn("<script>bad</script>", html)
        self.assertIn("&lt;script&gt;bad&lt;/script&gt;", html)
        self.assertNotIn("<img src=x>", html)

    def test_requirements_parser_only_accepts_exact_pins(self):
        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "requirements.txt"
            req.write_text(
                "requests==2.31.0\nflask>=2.0\n-e .\n# comment\nDjango==4.2.1\n"
            )
            packages, skipped = parse_requirements(req)
            self.assertEqual(
                [(x["name"], x["version"]) for x in packages],
                [("requests", "2.31.0"), ("django", "4.2.1")],
            )
            self.assertEqual(len(skipped), 1)


if __name__ == "__main__":
    unittest.main()
