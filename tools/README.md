# Harmonia toolbelt

Canonical tool contracts mined from the homeserver updater quarry and the live HomeConsole/Arcadia tranche. Tools are Rust-owned contracts; Python remains quarry compatibility only, not an authority lane.

- `archive` — Archive unpack/pack primitive for tar/zip release payloads.
- `artifact` — Artifact install/promote/rollback primitive for binaries and release payloads.
- `backup` — Backup/snapshot/preserve/restore primitive for mutable runtime state.
- `command` — Host command execution primitive with cwd/env/timeout/exit capture; every subprocess produces a command receipt.
- `config` — Typed config/JSON/TOML/YAML read/write/validate primitive.
- `cron-timer` — Cron/systemd timer install/enable/status primitive.
- `download` — HTTP download/version discovery primitive with bounded network calls and receipt evidence.
- `files` — Staged file/template/directory/symlink primitive with atomic promotion.
- `git-artifact` — Git branch/tag/artifact fetch primitive for source and release payloads.
- `health` — Service readiness and health-readback primitive, including HTTP and command checks.
- `hotfix` — Emergency one-shot hotfix primitive with explicit receipt and retirement path.
- `interactable` — Operator-triggered action primitive for manual buttons that still need receipts.
- `migration` — Ordered idempotent migration primitive with applied-state receipts.
- `node-build` — Node/npm/pnpm build primitive for web bodies.
- `package` — OS package check/update/install primitive; supports pacman first and later apt/dnf adapters.
- `permissions` — Owner/group/mode/ACL/sudoers policy primitive with validation before promotion.
- `receipt` — Central receipt writer and run ledger primitive.
- `rust-build` — Cargo build/test/install primitive for Rust bodies such as Arcadia and Harmonia.
- `systemd` — Systemd unit install/enable/disable/start/stop/restart/status primitive.
- `venv` — Python virtualenv preservation/update primitive for quarry compatibility surfaces; not a Harmonia authority lane.
- `version` — Version detection/compare/channel selection primitive.
