#!/usr/bin/env python3
"""Offline source-risk scanner. It never executes scanned code or uses the network."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

SOURCE_SUFFIXES = {
    ".lua", ".luau", ".js", ".jsx", ".ts", ".tsx", ".py",
    ".ps1", ".bat", ".cmd", ".sh", ".txt", ".json",
}
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "site-packages"}
MAX_SOURCE_BYTES = 2 * 1024 * 1024

# These are screening indicators, not a malware verdict. Any hit requires human review.
RULES = [
    ("HIGH", "Discord webhook endpoint", r"discord(?:app)?\.com/api/webhooks"),
    ("HIGH", "public-IP lookup service", r"(?:api\.)?ipify\.org|ipinfo\.io|ip-api\.com|ifconfig\.me"),
    ("HIGH", "credential or session-cookie access", r"ROBLOSECURITY|GetCookie|document\.cookie|Authorization\s*[:=]"),
    ("HIGH", "outbound POST/request primitive", r"HttpPost|PostAsync|axios\.post|requests\.post|http_request|syn\.request|request\s*\(\s*\{"),
    ("REVIEW", "dynamic code execution", r"loadstring\s*\(|\beval\s*\(|\bexec\s*\("),
    ("REVIEW", "remote fetch or loader", r"game\s*:\s*HttpGet|HttpGet\s*\(|fetch\s*\(|requests\.get|axios\.get"),
    ("REVIEW", "executor filesystem API", r"\b(?:readfile|writefile|appendfile|delfile|listfiles|makefolder|isfile|isfolder)\s*\("),
    ("REVIEW", "player identity/profile collection", r"GetCountryRegionForPlayerAsync|AccountAge|UserId|DisplayName"),
]
COMPILED_RULES = [(severity, label, re.compile(pattern, re.IGNORECASE)) for severity, label, pattern in RULES]


def scan_text(source: str) -> list[dict[str, Any]]:
    """Return rule hits without including potentially sensitive source lines."""
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        for severity, label, pattern in COMPILED_RULES:
            if pattern.search(line):
                findings.append({"severity": severity, "line": line_number, "rule": label})
    return findings


def scan_root(root: Path) -> tuple[int, list[dict[str, Any]]]:
    scanned = 0
    findings: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        relative = path.relative_to(root)
        if any(part in IGNORED_DIRS for part in relative.parts):
            continue
        # The detector contains the patterns it searches for; do not scan its own rule definitions.
        if relative.as_posix() == "tools/security_scan.py":
            continue
        scanned += 1
        try:
            size = path.stat().st_size
            if size > MAX_SOURCE_BYTES:
                findings.append({
                    "file": relative.as_posix(),
                    "severity": "REVIEW",
                    "line": 0,
                    "rule": "source exceeds 2 MiB; manual review required",
                })
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.append({
                "file": relative.as_posix(),
                "severity": "HIGH",
                "line": 0,
                "rule": "file could not be read for inspection",
            })
            continue
        for item in scan_text(source):
            item["file"] = relative.as_posix()
            findings.append(item)
    return scanned, findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Screen source files for common privacy/execution-risk indicators.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="directory to scan (default: current directory)")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"ERROR: scan root is not a directory: {root}", file=sys.stderr)
        return 2

    scanned, findings = scan_root(root)
    print(f"Scanned {scanned} candidate source file(s).")
    for item in findings:
        print(f"[{item['severity']}] {item.get('file', '<input>')}:{item['line']}: {item['rule']}")
    if findings:
        print(f"Review required: {len(findings)} finding(s). The scanner fails closed on any indicator.")
        return 1
    if scanned == 0:
        print("No script files are present to inspect; this is not a runtime safety certification.")
    else:
        print("No configured indicators found. This is not proof of safety; obfuscation and unseen remote code can evade static scans.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
