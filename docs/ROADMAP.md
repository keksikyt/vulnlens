# VulnLens Roadmap

VulnLens aims to make practical repository security checks accessible, local-first, and actionable.

## v0.2 — CI integrations
- [ ] SARIF 2.1.0 output for GitHub Code Scanning
- [ ] GitHub Action integration with least-privilege permissions
- [ ] Baseline file to track existing findings without hiding new ones
- [ ] HTML report with redacted evidence and severity filters

## v0.3 — Dependency security
- [ ] Parse Python requirements and supported lockfiles
- [ ] Optional OSV.dev vulnerability lookups with network access clearly disclosed
- [ ] Show affected and fixed version ranges with references
- [ ] Tests for vulnerable, patched, and unknown package versions

## v0.4 — Reliability
- [ ] Configurable rules and expiring suppressions with justification
- [ ] SARIF schema validation and golden-file tests
- [ ] Linux, macOS, and Windows CI
- [ ] Type checking, linting, coverage, and reproducible builds

## Community
- [ ] Publish security policy and private disclosure instructions
- [ ] Add good-first-issue labels and contribution guide
- [ ] Maintain release notes and a public changelog
- [ ] Publish benchmarks with transparent false-positive/false-negative limitations

## Principles
- Never print secret values or upload scanned source by default.
- Clearly label heuristic findings and unsupported formats.
- Only scan repositories and systems you own or are authorized to assess.
- Never claim a clean scan proves a project is secure.
