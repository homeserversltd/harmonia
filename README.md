# Harmonia

Harmonia is a Rust update manager and appliance-profile execution engine for HOMESERVER bodies.

It is not a Python updater and not a shell orchestration lane. Shell is allowed only as a bootstrap doorway. Harmonia owns the update covenant in Rust: identity selection, profile graph resolution, staged execution, reusable tools, promotion, receipts, and installer integration.

## North Star

- One public update organism.
- One possessed identity/profile per installed body.
- Ordered profile spines instead of ambient discovery.
- Reusable Rust tools packed/called by profiles through Harmonia's module engine.
- No false green: every failed stage becomes a nonzero process exit and a receipt with `ok=false`.
- Atomic staging and promotion before mutation of live paths.
- Central run receipts: `events.jsonl`, `run.json`, and module/tool matrix.
- Installer-bundled technology: binary, config, state dirs, systemd service, systemd timer, and receipt roots.
- HomeConsole and Arch Console are one profile family.

## Scaffold command

```text
cargo run -p harmonia -- explain
cargo run -p harmonia -- inspect-profile profiles/homeserver/index.json
cargo run -p harmonia -- plan-run profiles/homeconsole/index.json --receipt-dir /tmp/harmonia-receipts
```

`plan-run` is intentionally non-mutating in this first scaffold. It proves the spine/read/receipt shape before any machine receives a live update action.
