# Harmonia profiles

A Harmonia profile is the update plan for one class of machine.

Each installed machine selects exactly one profile. Harmonia uses that profile to decide which modules run, in what order, and which tools each module may call. This keeps updates predictable: the machine does not scan every possible module and guess what it should become at runtime.

## What a profile contains

A profile defines:

- an `id`, such as `homeconsole`;
- a `family`, such as `arch-console`;
- an ordered list of module names.

Example shape:

```json
{
  "id": "homeconsole",
  "family": "arch-console",
  "modules": [
    "identity",
    "system-packages",
    "keyman-runtime",
    "homeconsole-sync-runtime"
  ]
}
```

## How profiles run

```text
selected profile -> ordered module list -> Rust module registry/validation -> module manifests -> toolbelt execution -> receipts
```

Profiles provide order and scope. Modules are code-owned capability boundaries registered and validated in Rust. Module manifests declare ordered tool calls and inputs for registered modules. Tools perform the work.

## Current profile families

- `homeconsole` / `arch-console`: appliance console updates through code-owned modules for identity, system packages, Keyman runtime possession, and HomeConsole Sync runtime installation.
- Future families such as `homeserver` and `tv` must enter with Rust-registered module boundaries before profile manifests name them.

## Safety model

Profiles should be explicit and boring:

- one machine identity;
- one ordered module spine;
- no hidden runtime discovery;
- no JSON-only module authority;
- non-mutating checks available before `--apply`;
- receipts written for every run.
