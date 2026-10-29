# Security audit and cleanup record

Date: 2026-10-28
Repository: `dragonballls/Tr-Minh-hub`
Scope: static source inspection only; no original scripts were executed.

## Decision

The original repository contained multiple overlapping third-party hubs and loaders with outbound webhook reporting. Because it was not possible to establish that every runtime path was safe, the current branch removes those scripts rather than falsely labelling them safe.

## Confirmed privacy-risk patterns in the removed sources

- `windyhub.lua`: looks up the machine's public IP through an IP lookup service and sends it with the Roblox username to a Discord webhook.
- `9h16bbcaaak8289h29bbc928281682iccjhab.lua`: contains Discord webhook reporting of Roblox player/profile data (user ID, username/display name, country, account age, level/status) and a loader for additional remote code.
- `AnhTaibeta.lua`, `AnhTaibeta1.lua`, `Anhtai.txt`, `Khang_Mod_Game_Version_1.6.txt`, and `rimus_hub_1.lua`: contain webhook/outbound-post code; some also assemble player-profile details.
- `Xsea-2.js`: contains hard-coded Discord webhook endpoints and outbound posting logic.
- `Ak Gaming.txt`: an extremely large, effectively opaque source that could not be meaningfully reviewed through static inspection.

## Why the original target was not retained as “safe”

`x-seaHUB.txt` had no obvious direct webhook POST or clear Roblox-cookie read in the static scan, but it executes three dependencies downloaded at runtime (Fluent plus two add-ons). Their runtime behavior cannot be certified by inspecting the target file alone, and a mutable URL can change without a commit in this repository. A likely final-stage logic defect was also observed around a `Workspace.ReplicatedStorage` lookup and inconsistent Cursed Skeleton Boss name checks. No runtime test was performed.

## What this branch changes

- Removes all 25 script/source files from the current working tree.
- Replaces the minimal README with a security-first explanation.
- Adds this audit report.
- Adds `tools/security_scan.py`, an offline static pattern scanner that does not execute code or use the network.
- Adds unit tests and a GitHub Actions workflow for repeatable scans.
- Leaves the original `main` branch unchanged until this pull request is reviewed and merged.

## Limitations

The scanner is a defense-in-depth filter, not malware detection or a guarantee of safety. It may flag legitimate code and can miss obfuscated code, split strings, indirect behavior, or unseen remote dependencies. Every finding needs human review. A run with no source files means there was no script to inspect; it does not certify a runtime application.

Deleting files in a new commit does not erase their previous Git history, copies in the upstream repository, or files already downloaded to a computer. If a previously downloaded script was executed, stop using it and review the account and executor environment. Changing a GitHub branch does not clean a local machine.

This branch is a documentation and source-audit project, not a functioning game hub. It intentionally does not restore or operationalize game-exploit automation.
