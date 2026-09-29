# Contributing

Contributions of detection rules, tests, documentation, and bug reports are welcome. Small, focused pull requests are especially appreciated.

## Find something to work on

- Browse [good first issues](https://github.com/keksikyt/vulnlens/labels/good%20first%20issue) and open issues.
- If an issue is not assigned, comment that you would like to work on it before starting.
- For a substantial change, open an issue first so we can agree on the behavior and scope.

## Development

- Python 3.10+
- Install with: `python -m pip install -e .`
- Test with: `python -m unittest discover -s tests -v`

Before opening a pull request:

1. Keep the change focused and explain the user-visible behavior.
2. Add or update tests for bug fixes and new detection rules.
3. For detection rules, document false-positive considerations and include safe synthetic fixtures.
4. Run the test suite and include the command and result in the PR description.
5. Update relevant documentation and CLI examples when behavior or flags change.

## Security and privacy

Never submit live credentials, private source code, customer data, or real vulnerability details that are not authorized for disclosure. Use clearly fake values in tests and examples. Only scan systems you own or are authorized to assess.

If you believe you found a security vulnerability in VulnLens itself, do not open a public issue with exploit details. Follow the private reporting instructions in [SECURITY.md](SECURITY.md).

## Pull request review

Please describe what changed, why it is needed, how it was tested, and any known limitations. Maintainers may request changes or additional tests before merging. By submitting a contribution, you agree that it may be distributed under the repository's existing license.
