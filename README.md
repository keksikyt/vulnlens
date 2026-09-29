# VulnLens 🔎

**Local-first security checks for developers.** Find potential secrets, risky Dockerfile patterns, and GitHub Actions workflow misconfigurations before they reach production.

[![CI](https://github.com/keksikyt/vulnlens/actions/workflows/ci.yml/badge.svg)](https://github.com/keksikyt/vulnlens/actions/workflows/ci.yml) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

> **Alpha:** heuristic checks can produce false positives and miss issues. A clean scan is not proof of security.

## Features

- Detects patterns resembling credentials and private keys; matched values and source lines are never printed.
- Checks Dockerfiles for root users, remote URL use with `ADD`, and missing `USER` instructions.
- Checks GitHub Actions for action references using mutable branch/version tags and broad `write-all` permissions.
- Supports JSON output and CI exit thresholds.
- Runs locally without an API key or uploading source code.

## Install

Requires Python 3.10+.

```bash
python -m pip install .
```

For development: `python -m pip install -e .`

## Quick start

```bash
vulnlens .
vulnlens . --json vulnlens-report.json
vulnlens . --fail-on high
```

`--fail-on` supports `critical`, `high`, `medium`, `low`, and `never`. Exit status is non-zero when a finding meets the selected threshold.

## GitHub Actions

A basic CI workflow is included in `.github/workflows/ci.yml`. In your own repository, after checkout and Python setup, install and run:

```yaml
- run: python -m pip install .
- run: vulnlens . --json report.json --fail-on high
```

For production workflows, pin third-party actions to full commit SHAs and use least-privilege permissions.

## Rules

| Rule | Detection | Suggested action |
|---|---|---|
| VL001 | Potential credential/private-key pattern | Revoke and rotate real credentials; remove from source and use a secret manager |
| VL101 | Dockerfile explicitly runs as root | Use a dedicated unprivileged user |
| VL102 | Dockerfile downloads a remote URL with `ADD` | Verify integrity; prefer checksum-verified downloads or `COPY` |
| VL103 | No Dockerfile `USER` instruction | Assess runtime user and add non-root user where appropriate |
| VL201 | GitHub Action uses a branch or version tag | Pin action to a full commit SHA |
| VL202 | Broad `write-all` workflow permissions | Apply least privilege |

This release does **not** yet audit dependency vulnerability databases, resolve lockfiles, validate whether credentials are live, or inspect remote infrastructure. Dependency auditing and SARIF/HTML reports are roadmap items, not current features.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Roadmap

- [ ] Dependency vulnerability database integration and lockfile parsing
- [ ] SARIF output for GitHub Code Scanning
- [ ] HTML report and severity filters
- [ ] Expiring allowlist with justification
- [ ] More ecosystem and infrastructure-as-code rules

## License

MIT — see [LICENSE](LICENSE).
