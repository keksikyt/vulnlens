import json
import unittest
from unittest.mock import patch

from vulnlens.deps import query_osv


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


class OsvResponseValidationTests(unittest.TestCase):
    package = [{"name": "demo", "version": "1.0", "line": 1}]

    def run_with_payload(self, payload):
        with patch("vulnlens.deps.urlopen", return_value=FakeResponse(payload)):
            return query_osv(self.package)

    def test_rejects_non_list_vulnerabilities(self):
        with self.assertRaisesRegex(RuntimeError, "invalid vulnerability list"):
            self.run_with_payload({"results": [{"vulns": {}}]})

    def test_rejects_non_object_vulnerability(self):
        with self.assertRaisesRegex(RuntimeError, "invalid vulnerability list"):
            self.run_with_payload({"results": [{"vulns": ["CVE-2025-0001"]}]})

    def test_rejects_invalid_aliases(self):
        with self.assertRaisesRegex(RuntimeError, "invalid vulnerability aliases"):
            self.run_with_payload({"results": [{"vulns": [{"aliases": "CVE-2025-0001"}]}]})

    def test_rejects_invalid_references(self):
        with self.assertRaisesRegex(RuntimeError, "invalid vulnerability references"):
            self.run_with_payload({"results": [{"vulns": [{"references": ["https://example.com"]}]}]})

    def test_sanitizes_unexpected_optional_fields(self):
        findings = self.run_with_payload({"results": [{"vulns": [
            {"id": 7, "summary": 42, "modified": False, "references": [{"url": 12}],
             "aliases": []}
        ]}]})
        self.assertEqual(findings[0]["id"], "UNKNOWN")
        self.assertEqual(findings[0]["summary"], "No summary provided.")
        self.assertEqual(findings[0]["references"], [])
        self.assertIsNone(findings[0]["modified"])


if __name__ == "__main__":
    unittest.main()
