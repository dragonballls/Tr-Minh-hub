#!/usr/bin/env python3
"""Offline source-risk scanner. It never executes scanned code or uses the network."""
from __future__ import annotations
import argparse
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

SOURCE_SUFFIXES = {
    ".lua", ".luau", ".js", ".jsx", ".ts", ".tsx", ".py",
    ".ps1", ".psm1", ".bat", ".cmd", ".sh", ".txt", ".json",
    ".html", ".htm", ".xml", ".yaml", ".yml", ".php", ".rb",
    ".go", ".rs", ".java", ".cs",
}
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "site-packages"}
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_CANDIDATE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000

# Screening indicators, not a malware verdict. Any hit requires human review.
RULES = [
    ("HIGH", "Discord webhook endpoint", r"discord(?:app)?\.com/api/webhooks"),
    ("HIGH", "public-IP lookup service", r"(?:api\.)?ipify\.org|ipinfo\.io|ip-api\.com|ifconfig\.me"),
    ("HIGH", "credential or session-cookie access", r"ROBLOSECURITY|GetCookie|document\.cookie|Authorization\s*[:=]"),
    ("HIGH", "outbound POST/request primitive", r"HttpPost|PostAsync|axios\.post|requests\.post|http_request|syn\.request|request\s*\(\s*\{"),
    ("REVIEW", "dynamic code execution", r"loadstring\s*\(|\beval\s*\(|\bexec\s*\("),
    ("REVIEW", "remote fetch or loader", r"game\s*:\s*HttpGet|HttpGet\s*\(|fetch\s*\(|requests\.get|axios\.get|URLSession"),
    ("REVIEW", "executor filesystem API", r"\b(?:readfile|writefile|appendfile|delfile|listfiles|makefolder|isfile|isfolder)\s*\("),
    ("REVIEW", "player identity/profile collection", r"GetCountryRegionForPlayerAsync|AccountAge|UserId|DisplayName"),
]
COMPILED_RULES = [(level, label, re.compile(pattern, re.IGNORECASE)) for level, label, pattern in RULES]


def scan_text(source: str) -> list[dict[str, Any]]:
    """Return rule hits without printing or returning potentially sensitive source lines."""
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        for level, label, pattern in COMPILED_RULES:
            if pattern.search(line):
                findings.append({"severity": level, "line": line_number, "rule": label})
    return findings


def _candidate(name: str) -> bool:
    return PurePosixPath(name.replace("\\", "/")).suffix.lower() in SOURCE_SUFFIXES


def _ignored(name: str) -> bool:
    return any(part in IGNORED_DIRS for part in PurePosixPath(name.replace("\\", "/")).parts)


def _with_file(source: str, display_name: str) -> list[dict[str, Any]]:
    items = scan_text(source)
    for item in items:
        item["file"] = display_name
    return items


def scan_root(root: Path) -> tuple[int, list[dict[str, Any]]]:
    """Scan source-like files in a directory without following symlinks."""
    scanned = 0
    findings: list[dict[str, Any]] = []
    try:
        paths = sorted(root.rglob("*"))
    except OSError:
        return 0, [{"file": str(root), "severity": "HIGH", "line": 0, "rule": "directory could not be enumerated"}]
    for path in paths:
        try:
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if not _candidate(relative) or _ignored(relative) or relative == "tools/security_scan.py":
            continue
        scanned += 1
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                findings.append({"file": relative, "severity": "REVIEW", "line": 0, "rule": "source exceeds 2 MiB; manual review required"})
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            findings.append({"file": relative, "severity": "HIGH", "line": 0, "rule": "file could not be read for inspection"})
            continue
        findings.extend(_with_file(source, relative))
    return scanned, findings


def scan_archive(archive_path: Path) -> tuple[int, list[dict[str, Any]]]:
    """Inspect candidate files in a ZIP without extracting or executing them."""
    scanned = 0
    findings: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                return 0, [{"file": archive_path.name, "severity": "REVIEW", "line": 0, "rule": "archive contains over 10,000 entries; manual review required"}]
            total = 0
            for entry in entries:
                name = entry.filename
                if entry.is_dir() or not _candidate(name) or _ignored(name):
                    continue
                scanned += 1
                display = f"{archive_path.name}!/{name}"
                if entry.flag_bits & 0x1:
                    findings.append({"file": display, "severity": "HIGH", "line": 0, "rule": "encrypted source cannot be inspected"})
                    continue
                if entry.file_size > MAX_SOURCE_BYTES:
                    findings.append({"file": display, "severity": "REVIEW", "line": 0, "rule": "source exceeds 2 MiB; manual review required"})
                    continue
                total += entry.file_size
                if total > MAX_ARCHIVE_CANDIDATE_BYTES:
                    findings.append({"file": archive_path.name, "severity": "REVIEW", "line": 0, "rule": "archive candidate contents exceed 64 MiB; manual review required"})
                    break
                try:
                    raw = archive.read(entry)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    findings.append({"file": display, "severity": "HIGH", "line": 0, "rule": "archive entry could not be read"})
                    continue
                if len(raw) > MAX_SOURCE_BYTES:
                    findings.append({"file": display, "severity": "REVIEW", "line": 0, "rule": "decompressed source exceeds 2 MiB; manual review required"})
                    continue
                findings.extend(_with_file(raw.decode("utf-8", errors="replace"), display))
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        findings.append({"file": archive_path.name, "severity": "HIGH", "line": 0, "rule": "archive is missing, unreadable, or not a valid ZIP file"})
    return scanned, findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline screen for common source privacy and execution-risk indicators.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="directory to scan (default: current directory)")
    parser.add_argument("--archive", action="append", type=Path, default=[], help="inspect a ZIP without extracting it; may be repeated")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"ERROR: scan root is not a directory: {root}", file=sys.stderr)
        return 2
    scanned, findings = scan_root(root)
    for archive in args.archive:
        count, archive_findings = scan_archive(archive)
        scanned += count
        findings.extend(archive_findings)
    print(f"Scanned {scanned} candidate source file(s).")
    for item in findings:
        print(f"[{item['severity']}] {item.get('file', '<input>')}:{item['line']}: {item['rule']}")
    if findings:
        print(f"Review required: {len(findings)} finding(s). The scanner fails closed on any indicator.")
        return 1
    if not scanned:
        print("No script files were present to inspect; this is not a runtime safety certification.")
    else:
        print("No configured indicators found. This is not proof of safety; obfuscation and unseen remote code can evade static scans.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
