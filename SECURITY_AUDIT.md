# Security audit and cleanup record

Date: 2026-10-28
Repository: `dragonballls/Tr-Minh-hub`
Scope: static source inspection only; no original scripts were executed.

## Decision

The original repository contained overlapping third-party hubs and loaders with outbound webhook reporting. Because it was not possible to establish that every runtime path was safe, the current branch removes those scripts rather than falsely labelling them safe.

## Confirmed privacy-risk patterns in the removed sources

- `windyhub.lua`: looked up the machine's public IP through an IP lookup service and sent it with the Roblox username to a Discord webhook.
- `9h16bbcaaak8289h29bbc928281682iccjhab.lua`: contained Discord webhook reporting of Roblox player/profile data (user ID, username/display name, country, account age, level/status) and a loader for additional remote code.
- `AnhTaibeta.lua`, `AnhTaibeta1.lua`, `Anhtai.txt`, `Khang_Mod_Game_Version_1.6.txt`, and `rimus_hub_1.lua`: contained webhook/outbound-post code; some also assembled player-profile details.
- `Xsea-2.js`: contained hard-coded Discord webhook endpoints and outbound posting logic.
- `Ak Gaming.txt`: an extremely large, effectively opaque source that could not be meaningfully reviewed through static inspection.

## Why the original game script was not retained

The target file had no obvious direct webhook POST or clear Roblox-cookie read in its static scan, but it executed three dependencies downloaded at runtime. Their runtime behavior could not be certified by inspecting the target file alone, and mutable URLs can change independently of this repository. A likely logic defect was also observed in the final-stage code. No runtime test was performed.

## What the current repository provides

- Removes all 25 original script/source files from the current working tree.
- Adds this audit report and a security-focused README.
- Adds `tools/security_scan.py`, an offline static pattern scanner that does not execute code or use the network.
- Scans source-like files in directories and ZIP archives without extracting the archives.
- Limits source-file size, ZIP entry count, and total scanned candidate data.
- Adds unit tests and a GitHub Actions workflow for repeatable checks.

## Limitations

The scanner is a defense-in-depth filter, not malware detection or a safety guarantee. It may flag legitimate code and miss obfuscated code, split strings, indirect behavior, or unseen remote dependencies. Every finding needs human review. A scan with no source files does not certify a runtime application.

Removing files from the current Git tree does not erase old Git history, upstream copies, or files already downloaded to a computer. If an old script was run, stop using it and review your account security and the environment in which it ran. Changing a repository branch does not clean a local machine.

This is a source-review project, not a functioning game hub. It intentionally does not restore or operationalize game-exploit automation.
