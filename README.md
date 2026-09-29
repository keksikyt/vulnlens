# VulnLens 🔎

**Local-first repository security checks for developers.** Detect potential leaked secrets, risky Dockerfile patterns, and GitHub Actions workflow misconfigurations. Export SARIF to GitHub Code Scanning and track existing findings with a baseline.

[![CI](https://github.com/keksikyt/vulnlens/actions/workflows/ci.yml/badge.svg)](https://github.com/keksikyt/vulnlens/actions/workflows/ci.yml) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

> **Alpha software:** detection is heuristic. False positives and false negatives are possible; a clean scan is not proof of security.

## Features

- Secret-pattern detection with redacted output (the matching line/value is never emitted).
- Dockerfile checks for explicit root user, remote URL downloads with `ADD`, and missing `USER`.
- GitHub Actions checks for action references not pinned to a full commit SHA and broad `write-all` permissions.
- JSON and SARIF 2.1.0 output, stable fingerprints, baseline suppressions, and CI exit thresholds.
- Local-first: no API key or source upload required by the scanner.
- GitHub Actions workflow tests Python 3.10–3.13 and uploads SARIF on pushes/manual runs (requires Code Scanning availability for the repository).

## Install

Requires Python 3.10+.

```bash
python -m pip install .
```

For development: `python -m pip install -e .`

## Quick start

```bash
# Scan current directory
vulnlens .

# Machine-readable JSON and GitHub SARIF
vulnlens . --json report.json --sarif vulnlens.sarif

# Fail CI on high or critical findings
vulnlens . --fail-on high
```

`--fail-on` supports `critical`, `high`, `medium`, `low`, and `never`. Exit status is non-zero when a non-suppressed finding meets the threshold.

## Baselines

Create a baseline of current findings, then use it to fail only on new findings:

```bash
vulnlens . --write-baseline .vulnlens-baseline.json
vulnlens . --baseline .vulnlens-baseline.json --fail-on medium
```

Commit the baseline file if you want the whole team/CI to share it. Fingerprints include rule, path, line, and message; moving code may change a fingerprint. Review and refresh baselines deliberately—do not use them to conceal unresolved risk.

## GitHub Code Scanning

The included workflow generates SARIF and uploads it on pushes and manual workflow runs. Open the repository's **Security → Code scanning** tab to review results after a successful workflow. Availability depends on GitHub plan/repository settings. The workflow uses `security-events: write` only for the SARIF upload job; pull requests run tests without attempting to upload SARIF.

For your own workflow, generate SARIF with:

```yaml
- run: python -m pip install .
- run: vulnlens . --sarif vulnlens.sarif
```

Then upload the file with GitHub's supported SARIF upload action and grant the job only the required `security-events: write` permission. Pin third-party actions to verified full commit SHAs in production.

## Rules

| Rule | Detection | Suggested action |
|---|---|---|
| VL001 | Potential credential/private-key pattern | Revoke/rotate real credentials, remove from source/history where appropriate, and use a secret manager |
| VL101 | Dockerfile explicitly runs as root | Use a dedicated unprivileged user |
| VL102 | Dockerfile downloads a remote URL with `ADD` | Verify artifact integrity; prefer checksum-verified downloads or `COPY` |
| VL103 | No Dockerfile `USER` instruction | Assess runtime user and add non-root user where appropriate |
| VL201 | GitHub Action is not pinned to a full 40-character commit SHA | Pin to a verified immutable commit SHA |
| VL202 | Workflow grants `write-all` permissions | Apply least privilege |

VulnLens does **not** yet query vulnerability databases, parse dependency lockfiles, validate whether a detected credential is live, or inspect remote infrastructure. Dependency auditing and HTML reports remain planned features.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the [roadmap](docs/ROADMAP.md).

## Community

Bug reports, carefully tested detection rules, documentation improvements, and pull requests are welcome. Never commit real credentials or private customer data. Only scan systems you own or have permission to assess.

## License

MIT — see [LICENSE](LICENSE).
