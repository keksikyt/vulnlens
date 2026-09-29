# VulnLens 🔎

**Local-first repository security checks for developers.** Detect potential leaked secrets, risky Dockerfile patterns, and GitHub Actions workflow misconfigurations. Export SARIF to GitHub Code Scanning, baseline existing findings, and optionally audit pinned Python packages against OSV.dev.

[![CI](https://github.com/keksikyt/vulnlens/actions/workflows/ci.yml/badge.svg)](https://github.com/keksikyt/vulnlens/actions/workflows/ci.yml) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

> **Alpha:** heuristics and vulnerability databases have limitations. False positives and false negatives are possible; a clean scan is not proof of security.

## Features

- Secret-pattern detection with redacted output; matched values and source lines are never emitted.
- Dockerfile checks for root users, remote URL downloads with `ADD`, and missing `USER` instructions.
- GitHub Actions checks for references not pinned to a full commit SHA and broad `write-all` permissions.
- JSON and SARIF 2.1.0 output, stable fingerprints, baseline suppressions, and CI exit thresholds.
- Optional OSV.dev audit for exact-pinned Python requirements (network request; sends package names and versions only).
- Local-first scanner: no account, API key, or source upload required.

## Install

Requires Python 3.10+.

```bash
python -m pip install .
# Or for development
python -m pip install -e .
```

## Quick start

```bash
vulnlens .
vulnlens . --json report.json --sarif vulnlens.sarif --html report.html
vulnlens . --fail-on high
```

`--fail-on` supports `critical`, `high`, `medium`, `low`, and `never`. Exit status is non-zero when a non-suppressed finding meets the threshold.

## HTML reports

Generate a self-contained HTML report for local review:

```bash
vulnlens . --html vulnlens-report.html
```

The report escapes scanned text before rendering. Review it before sharing because repository paths and finding details may be sensitive.

## Reuse as a GitHub Action

After committing or tagging a reviewed release, consume the composite action from another workflow (replace `main` with a reviewed immutable commit SHA for production):

```yaml
name: VulnLens
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: keksikyt/vulnlens@main
        with:
          fail-on: high
```

The action installs this project from GitHub and creates SARIF and HTML files in the workspace. To upload SARIF to Code Scanning, add GitHub’s SARIF upload action in a separate job with narrowly scoped `security-events: write` permission.

## Baselines

Create a baseline of current findings and then fail only on new findings:

```bash
vulnlens . --write-baseline .vulnlens-baseline.json
vulnlens . --baseline .vulnlens-baseline.json --fail-on medium
```

Commit the baseline if the team should share it. Fingerprints include rule, path, line, and message, so moving code can change a fingerprint. Review baselines periodically; do not use them to conceal unresolved risk.

## Python dependency audit (OSV)

The separate `vulnlens-deps` command checks exact-pinned requirements against [OSV.dev](https://osv.dev):

```bash
vulnlens-deps requirements.txt
vulnlens-deps requirements.txt --json osv-report.json
```

Only exact `package==version` entries are queried. Ranges, editable installs, URLs, and other unsupported forms are reported as skipped rather than guessed. This command makes a network request to OSV.dev with package names and versions; it does not upload project source. It depends on OSV coverage and is not a complete software composition analysis solution.

## GitHub Code Scanning

The included workflow tests Python 3.10–3.13 and uploads SARIF on pushes and manual runs. After a successful workflow, review the repository's **Security → Code scanning** tab. Availability depends on GitHub repository settings and plan. Pull requests run tests without attempting SARIF upload.

For your own workflow, generate SARIF with `vulnlens . --sarif vulnlens.sarif`, then upload it using GitHub's supported SARIF upload action with the required `security-events: write` permission. Pin third-party actions to verified full commit SHAs in production.

## Rules

| Rule | Detection | Suggested action |
|---|---|---|
| VL001 | Potential credential/private-key pattern | Revoke/rotate real credentials, remove from source/history where appropriate, and use a secret manager |
| VL101 | Dockerfile explicitly runs as root | Use a dedicated unprivileged user |
| VL102 | Dockerfile downloads a remote URL with `ADD` | Verify artifact integrity; prefer checksum-verified downloads or `COPY` |
| VL103 | No Dockerfile `USER` instruction | Assess runtime user and add non-root user where appropriate |
| VL201 | GitHub Action is not pinned to a full 40-character commit SHA | Pin to a verified immutable SHA |
| VL202 | Workflow grants `write-all` permissions | Apply least privilege |

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md), and [roadmap](docs/ROADMAP.md).

## Community

Issues and pull requests for tested rules, documentation, and bug fixes are welcome. Never commit live credentials or private customer data. Only scan systems you own or have permission to assess.

## License

MIT — see [LICENSE](LICENSE).
