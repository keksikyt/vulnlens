# VulnLens community launch kit

This document contains ready-to-adapt copy and a practical checklist for introducing VulnLens to developer communities. Please personalize posts to each community's rules and disclose that VulnLens is an alpha project.

## One-line description

VulnLens is a local-first Python security scanner for potential secrets, Dockerfile risks, GitHub Actions misconfigurations, and optionally exact-pinned Python dependencies via OSV.dev.

## Short project pitch

VulnLens helps developers add lightweight security checks to a repository without sending source code to a hosted scanning service. It scans locally, redacts detected secret values in findings, exports SARIF/JSON/HTML, supports baselines and CI thresholds, and includes an optional OSV.dev audit for exact-pinned requirements.

It is alpha software: detection is heuristic, coverage is limited, and a clean scan is not proof that a project is secure. Contributions, bug reports, and feedback are welcome.

## Launch post — Reddit / developer forums

**Title:** I built VulnLens, a local-first Python scanner for secrets, Dockerfiles and GitHub Actions — looking for feedback

Hi! I’m working on VulnLens, an open-source Python tool for adding a few practical security checks to a repository.

It currently checks for potential leaked secrets (with redacted findings), risky Dockerfile patterns, GitHub Actions SHA pinning and broad workflow permissions. It can emit SARIF, JSON and HTML, supports baselines and CI thresholds, and has an opt-in OSV.dev audit for exact-pinned Python requirements.

The goal is to keep the repository scan local rather than upload source code to a hosted service. The dependency audit is separate and sends package names and versions to OSV.dev.

It’s still alpha, so false positives and missed issues are possible. I’d especially appreciate feedback on:
- Which checks would be useful in your everyday workflow?
- Which formats or package managers should be supported next?
- Where is the output noisy or confusing?

Repository: https://github.com/keksikyt/vulnlens

Please share feedback or report issues in the repository. I’ll follow the rules of each community and won’t post repeatedly.

## Short post — X / Mastodon / Bluesky

I’m building VulnLens 🔎 — an open-source, local-first Python security scanner for potential secrets, Dockerfile risks, GitHub Actions misconfigurations, plus optional OSV dependency checks.

SARIF / JSON / HTML, baselines, CI thresholds. Alpha and looking for honest feedback and contributors.

https://github.com/keksikyt/vulnlens

## Short description for project directories

Local-first Python security checks for potential secrets, Dockerfiles, GitHub Actions and pinned Python dependencies. SARIF/JSON/HTML reports, baselines and CI thresholds. Open source, alpha.

## Before posting

- [ ] Confirm the default branch CI is green and link to the latest successful run.
- [ ] Check the README install instructions from a clean environment.
- [ ] Confirm the PyPI package/release status before advertising a pip install command; do not imply a release exists if it does not.
- [ ] Add a small, synthetic demo repository or screenshots with fake credentials only. Never publish real secrets or customer code.
- [ ] Check each community's self-promotion and project-launch rules; adapt the post and disclose your affiliation.
- [ ] Be explicit about alpha status, supported checks, limitations, and the network behavior of the OSV audit.
- [ ] Invite actionable feedback and respond respectfully to issues.

## Suggested outreach sequence

1. Publish one launch post in a community that explicitly allows project showcases.
2. Share a short personal update on social media linking to the repository and a concrete demo.
3. Submit to relevant open-source directories only after verifying their current submission rules.
4. Follow up with a technical post showing a synthetic finding, SARIF integration, or how to add VulnLens to CI.
5. Track questions and feature requests in GitHub Issues; avoid unsolicited mass messaging or repetitive cross-posting.
