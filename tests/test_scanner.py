import json
import tempfile
import unittest
from pathlib import Path
from vulnlens.cli import apply_baseline, scan, to_sarif, write_baseline

class ScannerTests(unittest.TestCase):
    def test_secret_is_detected_but_value_is_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'app.py').write_text('API_KEY = "thisIsARealisticSecret12345"\n')
            report=scan(root)
            self.assertEqual(report['summary']['total'],1)
            self.assertNotIn('thisIsARealisticSecret12345',str(report))

    def test_docker_root_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'Dockerfile').write_text('FROM python:3.12\nUSER root\n')
            self.assertTrue(any(x['rule']=='VL101' for x in scan(root)['findings']))

    def test_empty_tree(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(scan(Path(d))['summary']['total'],0)

    def test_sarif_format(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'Dockerfile').write_text('FROM alpine\nUSER root\n')
            sarif=to_sarif(scan(root))
            self.assertEqual(sarif['version'],'2.1.0')
            self.assertEqual(sarif['runs'][0]['tool']['driver']['name'],'VulnLens')
            self.assertTrue(sarif['runs'][0]['results'])

    def test_baseline_suppresses_existing_finding(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'Dockerfile').write_text('FROM alpine\nUSER root\n')
            report=scan(root)
            baseline=root/'baseline.json'
            write_baseline(report,baseline)
            apply_baseline(report,baseline)
            self.assertEqual(report['summary']['suppressed'],len(report['findings']))
            self.assertEqual(report['summary']['new'],0)

    def test_baseline_does_not_suppress_new_rule_location(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'Dockerfile').write_text('FROM alpine\nUSER root\n')
            baseline=root/'baseline.json'
            write_baseline(scan(root),baseline)
            (root/'Dockerfile').write_text('FROM alpine\nUSER root\nADD https://example.invalid/file /tmp/file\n')
            report=scan(root)
            apply_baseline(report,baseline)
            self.assertGreater(report['summary']['new'],0)

if __name__=='__main__':
    unittest.main()
