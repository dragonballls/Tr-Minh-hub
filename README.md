# Tr-Minh-hub — security-clean repository

This repository is intentionally a **security quarantine and source-review tool**, not a runnable game hub. The original third-party scripts were removed because static inspection found data-sharing webhooks, remote code loaders, and opaque sources that could not be verified.

## Run the offline source scan

Requires Python 3.10 or newer. The scanner uses only the Python standard library. It does not execute scanned code, make network requests, upload file contents, or extract ZIP archives.

```sh
python tools/security_scan.py --root .
python tools/security_scan.py --root . --archive "Downloads/script-bundle.zip"
python -m unittest discover -s tests -v
```

Use `--archive` multiple times to inspect multiple ZIPs. The scan checks source-like files in folders or archives for common indicators of webhook/data reporting, public-IP lookups, credential/session access, outbound POST requests, dynamic code execution, remote loaders, executor filesystem APIs, and player-profile collection. It limits individual source files to 2 MiB, ZIP entry count to 10,000, and total candidate contents per archive to 64 MiB.

**A clean scan is not proof that code is safe.** These are heuristic indicators; each finding requires human review. Obfuscation, split strings, indirect behavior, and code downloaded later can evade static checks. This tool does not run or sandbox scanned code.

GitHub Actions runs the unit tests and repository scan on pushes and pull requests. Avoid adding unverified scripts back into this project.

## Original scripts and history

The original scripts are not present in the current tree. This does not erase prior Git history, upstream copies, or local downloads. Do not run old copies from previous commits or other repositories.
