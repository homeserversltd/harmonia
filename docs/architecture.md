# Harmonia architecture

Harmonia updates through one lane:

Profile -> Identity -> literal Rust module logic + adjacent sidecar constants -> shared Rust tools -> receipt.

HomeConsole is the sole console identity. The HomeConsole profile is `profiles/homeconsole/index.json`; module-specific Rust logic and constants live together under `profiles/homeconsole/modules/<module>/index.rs` and `sidecar.json`. `src/module_dispatch.rs` is only the thin loader/dispatcher, and shared capability primitives live under `src/tools/*.rs`.

Sidecars are constants only: paths, repos, branches, packages, services, users, groups, modes, URLs, health endpoints, locks, state files, env file paths, and expected receipt families. Sidecars do not own sequencing, commands, ladders, recursive Harmonia invocation, or appliance identity.

Historical continuity is one ledger per profile, stored as JSONL under the receipts root, for example `homeconsole-ledger.jsonl`. Each module appends exactly one pass/fail entry per run with a stamp, sequence, run id, profile identity, module id, operation count, changed state, and first missing signal. Harmonia does not create per-module ledgers.

## Self-contained module currentness

A Harmonia module is a self-contained intent that must remain updated. The module owns the desired state for one appliance concern, the target surfaces that express that concern on the live body, the comparison that decides whether the concern is current, the safe mutation sequence that repairs drift, the domain-specific reconcile step, and the receipt schema that proves closure.

Shared tools provide primitives: file comparison, atomic promotion, command execution, package checks, systemd operations, health probes, and receipt writing. A tool does not decide what the appliance concern means. The module composes the tools in the lawful order for its own domain.

Managed-file modules follow the same update skeleton: render desired content from module-owned source, read the installed target, compare bytes and declared metadata, write only when drift exists, promote atomically, set ownership and mode, run the domain reconcile step, then receipt each file and the aggregate module. UDEV reconciles by reloading UDEV rules. Systemd reconciles by running `systemctl daemon-reload` and then applying the unit state declared by the module. Nginx would validate with `nginx -t` before reload. Firewall would validate and apply its ruleset. Every module remains one intent with its own currentness definition.
