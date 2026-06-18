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
    "harmonia-runtime",
    "keyman-runtime",
    "homeconsole-sync-runtime",
    "rust-build-toolchain",
    "arcadia-gui-runtime",
    "pinned-artifacts-runtime"
  ]
}
```

## How profiles run

```text
selected profile -> ordered module list -> Rust module registry/validation -> module manifests -> toolbelt execution -> receipts
```

Profiles provide order and scope. Modules are code-owned capability boundaries registered and validated in Rust. Module manifests declare ordered tool calls and inputs for registered modules. Tools perform the work.

## Current profile families

- `homeconsole` / `arch-console`: appliance console updates through the full code-owned suite spine for identity, system packages, Harmonia runtime possession, Keyman runtime possession, HomeConsole Sync runtime installation, Rust build toolchain possession, Arcadia GUI source/build/promote/service health, and pinned known-good artifact checks.
- `tv` / `arch-tv`: intentionally OS-only updates through identity and system packages. The TV profile must not inherit HomeConsole product runtimes or HomeServer service modules unless a future operator declaration adds a real owned component.
- Future families such as `homeserver` must enter with Rust-registered module boundaries before profile manifests name them.

## Safety model

Profiles should be explicit and boring:

- one machine identity;
- one ordered module spine;
- no hidden runtime discovery;
- no JSON-only module authority;
- non-mutating checks available before `--apply`;
- receipts written for every run.
