"""Generate conservative, review-only remediation patches; never edits source files."""
from __future__ import annotations
import argparse
import difflib
from pathlib import Path
import re
from .cli import MAX_BYTES, SKIP

def preview(root: str) -> str:
    base = Path(root).resolve()
    chunks = []
    for path in base.rglob("*"):
        if any(part in SKIP for part in path.parts) or path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() not in {".yml", ".yaml"} or ".github" not in path.parts or "workflows" not in path.parts:
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        lines = original.splitlines(keepends=True)
        changed = False
        out = []
        for line in lines:
            # Conservative: only propose replacing the explicit broad scalar.
            if re.match(r"^([ \t]*)permissions[ \t]*:[ \t]*write-all[ \t]*(?:#.*)?(?:\r?\n)?$", line, re.I):
                indent = re.match(r"^([ \t]*)", line).group(1)
                ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
                out.append(indent + "permissions: contents: read  # REVIEW: grant only permissions required by this workflow" + ending)
                changed = True
            else:
                out.append(line)
        if changed:
            diff = difflib.unified_diff(lines, out, fromfile="a/" + path.relative_to(base).as_posix(),
                                        tofile="b/" + path.relative_to(base).as_posix())
            chunks.extend(diff)
    return "".join(chunks) or "No conservative automatic patch candidates found. No files were modified.\n"

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--output", metavar="FILE", help="Write proposed unified diff to a file")
    args = parser.parse_args(argv)
    patch = preview(args.path)
    if args.output:
        Path(args.output).write_text(patch, encoding="utf-8")
    print(patch, end="" if patch.endswith("\n") else "\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
