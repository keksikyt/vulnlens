# Changelog

All notable changes to VulnLens are documented here.

## 0.2.0 — Security workflow improvements

- Add SARIF 2.1.0 output for GitHub Code Scanning.
- Add fingerprint-based baseline creation and suppression for existing findings.
- Improve GitHub Actions pinning checks to flag references not using full 40-character commit SHAs.
- Expand tests for SARIF and baseline behavior.
- Expand CI to Python 3.10–3.13 and add a SARIF upload job for pushes and manual runs.
- Update documentation and publish a development roadmap.

## 0.1.0 — Initial alpha

- Add local heuristic checks for secret-like patterns, Dockerfile risks, and GitHub Actions configuration.
- Add JSON output and initial CI tests.
