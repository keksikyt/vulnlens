import tempfile
import unittest
from pathlib import Path
from vulnlens.cli import scan

class ScannerTests(unittest.TestCase):
    def test_secret_is_detected_but_value_is_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'app.py').write_text('API_KEY = "thisIsARealisticSecret12345"\n')
            report=scan(root)
            self.assertEqual(report['summary']['total'],1)
            self.assertNotIn('thisIsARealisticSecret12345',str(report))
    def test_docker_root_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'Dockerfile').write_text('FROM python:3.12\nUSER root\n')
            self.assertTrue(any(x['rule']=='VL101' for x in scan(root)['findings']))
    def test_empty_tree(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(scan(Path(d))['summary']['total'],0)

if __name__=='__main__': unittest.main()
