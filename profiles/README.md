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
    "game-library",
    "desktop-appliance",
    "pinned-artifacts",
    "receipts"
  ]
}
```

## How profiles run

```text
selected profile -> ordered module list -> module manifests -> toolbelt execution -> receipts
```

Profiles provide order and scope. Modules provide step intent. Tools perform the work.

## Current profile families

- `homeconsole` / `arch-console`: appliance console updates, package state, pinned artifacts, game-library sync, and local UI/runtime health.
- `homeserver`: server update profile implemented through reusable tools.
- `tv`: appliance update profile for TV-style systems.

## Safety model

Profiles should be explicit and boring:

- one machine identity;
- one ordered module spine;
- no hidden runtime discovery;
- non-mutating checks available before `--apply`;
- receipts written for every run.
