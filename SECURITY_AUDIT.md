# Security audit and cleanup record

Date: 2026-10-28
Repository: `dragonballls/Tr-Minh-hub`
Scope: static source inspection only; no scripts were executed.

## Decision

This branch removes all third-party script files from the current working tree. The repository contained multiple overlapping hubs and loaders, several with outbound webhook reporting. It was not possible to provide a defensible guarantee that every remaining runtime path was safe, so this branch keeps documentation only.

## Confirmed privacy-risk patterns in the removed sources

- `windyhub.lua`: looks up the machine's public IP through an IP lookup service and sends it with the Roblox username to a Discord webhook.
- `9h16bbcaaak8289h29bbc928281682iccjhab.lua`: contains Discord webhook reporting of Roblox player/profile data (user ID, username/display name, country, account age, level/status) and a loader for more remote code.
- `AnhTaibeta.lua`, `AnhTaibeta1.lua`, `Anhtai.txt`, `Khang_Mod_Game_Version_1.6.txt`, and `rimus_hub_1.lua`: contain webhook/outbound-post code; some also assemble player-profile details.
- `Xsea-2.js`: contains hard-coded Discord webhook endpoints and outbound posting logic.
- `Ak Gaming.txt`: an extremely large, effectively opaque source that could not be meaningfully verified by the available static inspection.

## Why the intended CDK file was not retained as “safe”

`x-seaHUB.txt` had no obvious direct webhook POST or clear Roblox-cookie read found during its static scan, but it dynamically loads code from remote URLs (including mutable “latest”/branch URLs). Its behavior therefore depends partly on code that can change outside this repository. A likely final-stage logic defect was also observed around the `Workspace.ReplicatedStorage` lookup and inconsistent Cursed Skeleton Boss name checks. No runtime test was performed, and this branch does not attempt to repair or operationalize the exploit automation.

Other removed files also contained remote loaders, executor-specific filesystem APIs, outbound-post patterns, or could not be fully validated. A static pattern scan is not proof of malware or proof of safety; it is not possible to certify those files as non-stealing based on the available evidence.

## What this branch changes

- Removes all 25 script/source files from the current working tree.
- Replaces the minimal README with a warning describing this security-clean branch.
- Adds this audit record.
- Leaves the existing `main` branch untouched until this pull request is reviewed and merged.

## Important limits

Deleting files in a new commit does **not** erase their previous Git history, delete copies in the upstream repository, or remove files already downloaded to a computer. If an older copy has already been run, stop using it and review the security of the account and executor environment. Do not assume changing a repository branch cleans a local machine.

This branch deliberately has no runnable game scripts. It should be treated as a clean quarantine/documentation snapshot, not as a working hub.
