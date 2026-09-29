"""VulnLens: local-first heuristic security checks."""
from pathlib import Path
import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from .html_report import write_html

VERSION = "0.2.0"
SKIP = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build", ".tox"}
MAX_BYTES = 1_000_000
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PATTERNS = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Credential-like assignment", re.compile(r"""(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*['"]?[A-Za-z0-9_./+=-]{12,}""")),
    ("GitHub token pattern", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
]
RULES = {
    "VL001": ("Potential secret", "high"),
    "VL101": ("Docker container runs as root", "medium"),
    "VL102": ("Remote URL in Docker ADD", "low"),
    "VL103": ("Dockerfile has no USER instruction", "low"),
    "VL201": ("GitHub Action is not pinned to a commit SHA", "medium"),
    "VL202": ("GitHub Actions uses write-all permissions", "medium"),
}

def iter_files(root):
    for path in root.rglob("*"):
        if any(part in SKIP for part in path.parts):
            continue
        if path.is_file() and not path.is_symlink():
            try:
                if path.stat().st_size <= MAX_BYTES:
                    yield path
            except OSError:
                continue

def fingerprint(finding):
    raw = "|".join((finding["rule"], finding["file"], str(finding["line"]), finding["message"]))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def make_finding(rule, severity, path, line, message, remediation):
    item = {"rule": rule, "severity": severity, "file": path.as_posix(), "line": line,
            "message": message, "remediation": remediation}
    item["fingerprint"] = fingerprint(item)
    return item

def scan(root):
    root = Path(root).resolve()
    findings = []
    for path in iter_files(root):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            for label, pattern in PATTERNS:
                if pattern.search(line):
                    findings.append(make_finding("VL001", "high", path.relative_to(root), number,
                        "Possible " + label + " detected; value redacted.",
                        "Revoke and rotate any real credential, remove it from source/history where appropriate, and use a secret manager."))
                    break
        if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
            has_user = any(re.match(r"\s*USER\s+\S+", line, re.I) for line in lines)
            for number, line in enumerate(lines, 1):
                if re.match(r"^\s*USER\s+root\b", line, re.I):
                    findings.append(make_finding("VL101", "medium", path.relative_to(root), number,
                        "Container explicitly runs as root.", "Use a dedicated unprivileged user and USER instruction."))
                if re.match(r"^\s*ADD\s+https?://", line, re.I):
                    findings.append(make_finding("VL102", "low", path.relative_to(root), number,
                        "ADD downloads a remote URL.", "Verify artifact integrity; prefer checksum-verified downloads or COPY."))
            if not has_user:
                findings.append(make_finding("VL103", "low", path.relative_to(root), 1,
                    "No USER instruction found; image may run as root.",
                    "Add a non-root user and USER instruction where compatible."))
    workflow_dir = root / ".github" / "workflows"
    if workflow_dir.is_dir():
        for path in workflow_dir.rglob("*"):
            # Workflow files are untrusted input too: do not follow symlinks or
            # read oversized files (the same limit used by the source scanner).
            if (path.is_symlink() or not path.is_file()
                    or path.suffix.lower() not in {".yml", ".yaml"}):
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                match = re.search(r"\buses\s*:\s*([^\s#]+)", line)
                if match:
                    ref = match.group(1).rsplit("@", 1)
                    if len(ref) == 2 and not re.fullmatch(r"[0-9a-fA-F]{40}", ref[1]):
                        findings.append(make_finding("VL201", "medium", path.relative_to(root), number,
                            "Action reference is not pinned to a full 40-character commit SHA.",
                            "Pin third-party actions to a verified full commit SHA and retain the release tag in a comment."))
                if re.search(r"(?i)\bpermissions\s*:\s*write-all", line):
                    findings.append(make_finding("VL202", "medium", path.relative_to(root), number,
                        "Workflow grants broad write-all permissions.", "Use least-privilege token permissions at workflow or job level."))
    counts = {level: sum(f["severity"] == level for f in findings) for level in SEVERITY}
    return {"tool": "VulnLens", "version": VERSION, "target": str(root),
            "summary": {"total": len(findings), "by_severity": counts}, "findings": findings,
            "notice": "Heuristic results can include false positives and false negatives. Review findings; a clean scan is not proof of security."}

def apply_baseline(report, baseline_path):
    try:
        data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        known = set(data.get("fingerprints", []))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Could not read baseline: " + str(exc)) from exc
    for finding in report["findings"]:
        finding["suppressed"] = finding["fingerprint"] in known
    report["summary"]["suppressed"] = sum(f.get("suppressed", False) for f in report["findings"])
    report["summary"]["new"] = report["summary"]["total"] - report["summary"]["suppressed"]

def write_baseline(report, destination):
    data = {"schema": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
            "fingerprints": sorted({f["fingerprint"] for f in report["findings"]})}
    Path(destination).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

def to_sarif(report):
    results = []
    for f in report["findings"]:
        if f.get("suppressed"):
            continue
        results.append({
            "ruleId": f["rule"],
            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(f["severity"], "warning"),
            "message": {"text": f["message"] + " Remediation: " + f["remediation"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                            "region": {"startLine": max(1, f["line"])}}}],
            "partialFingerprints": {"vulnlens/v1": f["fingerprint"]},
        })
    rules = [{"id": rule, "shortDescription": {"text": desc},
              "defaultConfiguration": {"level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(sev, "note")}}
             for rule, (desc, sev) in RULES.items()]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "VulnLens", "version": VERSION, "rules": rules}},
                      "results": results}]}

def main(argv=None):
    parser = argparse.ArgumentParser(description="Local-first repository security checks")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--json", dest="json_file", metavar="FILE", help="Write JSON report")
    parser.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 report for GitHub Code Scanning")
    parser.add_argument("--html", metavar="FILE", help="Write a self-contained HTML report")
    parser.add_argument("--write-baseline", metavar="FILE", help="Save current finding fingerprints as a baseline")
    parser.add_argument("--baseline", metavar="FILE", help="Suppress findings already present in a baseline")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="never")
    args = parser.parse_args(argv)
    root = Path(args.path)
    if not root.is_dir():
        parser.error("path must be a directory")
    report = scan(root)
    if args.baseline:
        try:
            apply_baseline(report, args.baseline)
        except ValueError as exc:
            parser.error(str(exc))
    if args.write_baseline:
        write_baseline(report, args.write_baseline)
    print("VulnLens %s — %d finding(s)" % (VERSION, report["summary"]["total"]))
    for f in report["findings"]:
        status = " [BASELINED]" if f.get("suppressed") else ""
        print("[%s]%s %s:%s %s — %s\n  Fix: %s" %
              (f["severity"].upper(), status, f["file"], f["line"], f["rule"], f["message"], f["remediation"]))
    print(report["notice"])
    if args.json_file:
        Path(args.json_file).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.html:
        write_html(report, args.html)
    threshold = SEVERITY.get(args.fail_on, 99)
    new_findings = [f for f in report["findings"] if not f.get("suppressed")]
    return int(args.fail_on != "never" and any(SEVERITY[f["severity"]] <= threshold for f in new_findings))

if __name__ == "__main__":
    raise SystemExit(main())
