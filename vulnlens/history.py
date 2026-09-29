"""Local scan-history utility. Stores report metadata and findings locally; no network access."""
from __future__ import annotations
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from .cli import scan

def record(path: str, history_file: str) -> dict:
    target = Path(path).resolve()
    report = scan(target)
    entry = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "summary": report["summary"],
        "findings": [
            {k: f.get(k) for k in ("rule", "severity", "file", "line", "message", "fingerprint")}
            for f in report["findings"]
        ],
    }
    dest = Path(history_file).expanduser()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--history", default="~/.vulnlens/history.jsonl")
    parser.add_argument("--list", action="store_true", help="Print existing local history without scanning")
    args = parser.parse_args(argv)
    dest = Path(args.history).expanduser()
    if args.list:
        if dest.exists():
            print(dest.read_text(encoding="utf-8"), end="")
        return 0
    entry = record(args.path, str(dest))
    print(json.dumps({"recorded_at": entry["recorded_at"], "target": entry["target"],
                      "summary": entry["summary"], "history_file": str(dest)}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
