# Harmonia toolbelt

The Harmonia toolbelt is the public set of focused Rust primitives that profile modules call to update a machine.

A tool is executable behavior, not a configuration entry. Configuration can name a tool and pass inputs to it, but a new tool exists only when Rust code implements the behavior, a manifest records the contract, and tests prove the tool's seam.

## How modules use tools

```text
profile module -> tool name + inputs -> Rust tool execution -> receipt
```

For example, a module can declare that it needs the `systemd` tool to restart a service, or the `artifact` tool to promote a release binary. The module decides where the step sits in the profile order; the tool owns the action.

## Tool contract files

Each tool has a manifest at:

```text
tools/<tool>/index.json
```

The manifest is documentation and wiring metadata. The executable registry lives in:

```text
crates/harmonia/src/tools.rs
```

The code registry and manifest directory are tested together so public documentation and executable behavior stay aligned.

## Current tools

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
- `venv` — Python virtualenv preservation/update primitive for compatibility surfaces; not a Harmonia authority lane.
- `version` — Version detection/compare/channel selection primitive.

## Adding a tool

1. Add or extend the Rust implementation.
2. Add the tool to the code registry.
3. Add `tools/<tool>/index.json`.
4. Add focused tests for the tool seam.
5. Run `cargo test -p harmonia`.

If a change only adds JSON, it is module wiring or profile configuration, not a new tool.
