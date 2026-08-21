# Harmonia architecture

Harmonia executes one bounded ritual: **ask → compare → do → attest**. The ritual is typed, profile-scoped, and quiet when current.

## One-way layering

Atoms host primitive operations and engines: comparison, command capture, AUR, Git artifact, systemd, package, declaration, and `declarations.json` handling. Tools hold composition: the managed-files dispatcher, ordered routines, virtual-environment work, household-time work, artifact-lock compatibility work, and re-export seats. Bands call tools, and tools call atoms.

The direct-atom exception is intentional and narrow: `renew-self` uses the `replace_process` atom path. Other bands do not call atoms directly. The `do` surface contains twenty true-named transactional atoms in one folder per atom. Mutating atoms require diff-minted `Authorization` and the exact `--apply-or-timer` invocation key.

## Bands

The ten bands run in charter order: `renew-self`, `pull-source`, `stage-profile`, `compare`, `install-packages`, `ratchet-binaries`, `restart-services`, `backfill-files`, `propose-edits`, and `report-home`. `restart-services` precedes `backfill-files`.

## One demo door

The production demo surface is one command: `harmonia demo [<name>|list]`. The name is an argument, not a route. `demo` and `demo list` enumerate the same complete registry: `files-transaction`, `make-symlink`, `aur`, `git-artifact`, `systemd-unit`, `package`, `command`, `subscription-interactables`, `ladder-profile`, `renew-self`, `capsule`, `household-time`, `stillness`, `proposal-refresh`, `structural-wall`, `foundation`, `update-set`, `clock`, and `renew-schedule`. Every production tool has a live demo with a receipt through this door, and each demo preserves its existing behavior while observing its bounded cleanup.

## Checkable sources

- `src/atoms/index.json` names the atom floor and keys.
- `src/atoms/do/index.json` names the keyed transactional operation family.
- `src/bands/index.json` names the ten bands and their charter order.
- `src/tools/index.json` names the tool registry and composition entries.
