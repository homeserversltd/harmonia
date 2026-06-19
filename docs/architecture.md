# Harmonia architecture

Harmonia updates through one lane:

Profile -> Identity -> literal Rust module logic + adjacent sidecar constants -> shared Rust tools -> receipt.

HomeConsole is the sole console identity. The HomeConsole profile is `profiles/homeconsole/index.json`; its module constants live under `profiles/homeconsole/modules/<module>/sidecar.json`. Executable module behavior lives in Rust under `crates/harmonia/src/modules/`, and shared capability primitives live under `crates/harmonia/src/tools*.rs`.

Sidecars are constants only: paths, repos, branches, packages, services, users, groups, modes, URLs, health endpoints, locks, state files, env file paths, and expected receipt families. Sidecars do not own sequencing, commands, ladders, recursive Harmonia invocation, or appliance identity.
