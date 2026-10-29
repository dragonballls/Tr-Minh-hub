# Tr-Minh-hub — security-clean repository

This repository is intentionally a **security quarantine and source-review tool**, not a runnable game hub. The third-party scripts from the original fork were removed because static inspection found data-sharing webhooks, remote code loaders, and opaque sources that could not be verified.

## Run the source scan

Requires Python 3.10 or newer. The scanner uses only the Python standard library; it does not execute scanned code, send network requests, or upload file contents.

```sh
python tools/security_scan.py --root .
python -m unittest discover -s tests -v
```

The scanner fails when it finds common indicators of data exfiltration, credential access, dynamic code execution, remote loading, executor file access, or player-profile collection. Each finding requires manual review. **A clean scan is not proof that code is safe.**

A GitHub Actions workflow runs the unit tests and scan for pushes and pull requests. Keep new scripts out of this repository until their behavior and dependencies have been reviewed.

## Original scripts and history

The original scripts are not present in this branch's current tree. This does not erase older Git history, upstream copies, or local downloads. Do not run old copies from previous commits or other repositories.
