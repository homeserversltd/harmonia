# Harmonia architecture

Harmonia executes one bounded ritual: **ask → compare → do → attest**. The ritual is typed, profile-scoped, and quiet when current.

## One-way layering

Atoms host primitive operations and engines: comparison, command capture, AUR, Git artifact, systemd, package, declaration, and `declarations.json` handling. Tools hold composition: the managed-files dispatcher, ordered routines, virtual-environment work, household-time work, artifact-lock compatibility work, and re-export seats. Bands call tools, and tools call atoms.

The direct-atom exception is intentional and narrow: `renew-self` uses the `replace_process` atom path. Other bands do not call atoms directly. The `do` surface contains twenty true-named transactional atoms in one folder per atom. Mutating atoms require diff-minted `Authorization` and the exact `--apply-or-timer` invocation key.

## Bands

The eleven bands run in literal walk order: `renew-self`, `migrations`, `stage-profile`, `pull-source`, `compare`, `install-packages`, `ratchet-binaries`, `backfill-files`, `restart-services`, `propose-edits`, and `report-home`. Profile staging precedes source routines; managed-file backfill precedes service activation. These order corrections follow `3ad8d13c` (“Order managed files before service activation”) and `0e97c8e4` (“Order profile staging before source routines”). Rolling-update source acquisition is a prelude outside this band walk; it does not move the `pull-source` band ahead of profile staging.


## Checkable sources

- `src/atoms/index.json` names the atom floor and keys.
- `src/atoms/do/index.json` names the keyed transactional operation family.
- `src/bands/index.json` names the eleven bands and their charter order.
- `src/tools/index.json` names the tool registry and composition entries.

## Demo door

The single demo door is `harmonia demo [<name>|list]`; its only live entry is `quiescence`.
