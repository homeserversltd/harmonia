# Harmonia architecture

Harmonia executes one bounded ritual: **ask → compare → do → attest**. The ritual is typed, profile-scoped, and quiet when current.

## One-way layering

Atoms host primitive operations and engines: comparison, command capture, AUR, Git artifact, systemd, package, declaration, and `declarations.json` handling. Tools hold composition: the managed-files dispatcher, ordered routines, virtual-environment work, household-time work, artifact-lock compatibility work, and re-export seats. Bands call tools, and tools call atoms.

The direct-atom exception is intentional and narrow: `renew-self` uses the `replace_process` atom path. Other bands do not call atoms directly. The `do` surface contains twenty true-named transactional atoms in one folder per atom. Mutating atoms require diff-minted `Authorization` and the exact `--apply-or-timer` invocation key.

## Bands

The ten bands run in charter order: `renew-self`, `pull-source`, `stage-profile`, `compare`, `install-packages`, `ratchet-binaries`, `restart-services`, `backfill-files`, `propose-edits`, and `report-home`. `restart-services` precedes `backfill-files`.

## Bench routes

A bench is a real production walk with a scratch root and a receipt. The Slice 4 routes are `bench-slice4-files-transaction`, `bench-slice4-make-symlink`, `bench-slice4-aur`, `bench-slice4-git-artifact`, `bench-slice4-systemd-unit`, `bench-slice4-package`, `bench-slice4-command`, `bench-slice4-subscription-interactables`, `bench-slice4-ladder-profile`, `bench-slice4-renew-self`, `bench-slice4-capsule`, and `bench-slice4-household-time`. Pre-existing bench routes remain available: `bench-proposal-refresh`, `bench-structural-wall`, `bench-stillness`, `bench-harmonia-foundation`, `bench-update-set`, `bench-slice12-clock`, and `bench-slice13-renew-schedule`.

## Checkable sources

- `src/atoms/index.json` names the atom floor and keys.
- `src/atoms/do/index.json` names the keyed transactional operation family.
- `src/bands/index.json` names the ten bands and their charter order.
- `src/tools/index.json` names the tool registry and composition entries.
