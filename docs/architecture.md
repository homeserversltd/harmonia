# Harmonia architecture

Harmonia updates through one lane:

Profile -> Identity -> literal Rust module logic + adjacent sidecar constants -> shared Rust tools -> receipt.

HomeConsole is the sole console identity. The HomeConsole profile is `profiles/homeconsole/index.json`; module-specific Rust logic and constants live together under `profiles/homeconsole/modules/<module>/index.rs` and `sidecar.json`. `src/module_dispatch.rs` is only the thin loader/dispatcher, and shared capability primitives live under `src/tools/*.rs`.

Sidecars are constants only: paths, repos, branches, packages, services, users, groups, modes, URLs, health endpoints, locks, state files, env file paths, and expected receipt families. Sidecars do not own sequencing, commands, ladders, recursive Harmonia invocation, or appliance identity.

Historical continuity is one ledger per profile, stored as JSONL under the receipts root, for example `homeconsole-ledger.jsonl`. Each module appends exactly one pass/fail entry per run with a stamp, sequence, run id, profile identity, module id, operation count, changed state, and first missing signal. Harmonia does not create per-module ledgers.
