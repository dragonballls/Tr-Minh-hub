# Tr-Minh-hub — Security-clean review branch

This branch is a **quarantine snapshot**, not a functioning game hub. It intentionally contains no runnable third-party scripts.

The original files included code that sent player/device information to remote webhooks, remote code loaders, and scripts that could not be reliably reviewed. They have been removed from this branch's current tree rather than being labelled safe without evidence.

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the findings and limitations.

**Important:** the original `main` branch and previous Git history are not erased by this proposal. Older versions may still contain the removed scripts. Do not run those older copies. This branch cannot automate any in-game tasks, by design.
