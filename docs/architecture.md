# Harmonia architecture

Harmonia executes one bounded ritual: **ask → compare → do → attest**. The ritual is typed, profile-scoped, and quiet when current.

## Authorization and atoms

The engine carries two keys: diff-minted `Authorization` and the exact `--apply-or-timer` invocation key. The command face mints the invocation key once; mutation receives it by value. A bare update can ask and compare but cannot perform a deed.

`src/atoms/ask/` owns bounded observations. `src/atoms/do/` is the only mutation vocabulary: twenty true-named transactional do atoms, each admitted only with both keys. `src/atoms/attest/` recursively redacts caller-injected secret substrings before serialization, then appends the redacted `Receipt` and forwards fields derived from that same redacted value. There is no second mutation path.

## Declarations and registry

`src/tools/index.json` is the single registry. Its `declarations.records` contains exactly thirteen declaration records: place-file/place/copy-file; remove-file/remove/remove-file; make-symlink/link/make-link; enable-unit/enable/change-unit; remove-unit/remove/change-unit; backfill-file/backfill/copy-file; build-venv/converge/build-venv; build-crate/build/build-crate; set-clock/set/set-clock; pull-repo/acquire/pull-repo; install-package/install/install-package; check-health/probe/read-only; and ratchet-aur-package/build-pinned/install-aur-pinned. Each record uses phases `observe → compare → act → attest`, except read-only `check-health`, which omits `act`/`do` and still attests. `service-runtime` is a separate registry entry lowered to primitives, not one of the thirteen declaration records.

## Bands

The ten bands are entered in charter order:

1. `renew-self`
2. `pull-source`
3. `stage-profile`
4. `compare`
5. `install-packages`
6. `ratchet-binaries`
7. `restart-services`
8. `backfill-files`
9. `propose-edits`
10. `report-home`

`restart-services` runs before `backfill-files`. The charter order and band identifiers are the checkable band facts; `restart-services` precedes `backfill-files`.

## Profiles and closing state

Profiles declare an ordered module spine. Modules select declarations and compose their own observations, comparisons, deeds, and attestations within the one ritual. The engine's closing census is zero when no required signal is missing; the corresponding run result uses `first_missing_signal=none`.

## Checkable sources

- `src/atoms/index.json` names the atom floor and the two keys.
- `src/atoms/do/index.json` names the keyed transactional operation family.
- `src/bands/index.json` names the ten bands and their charter order.
- `src/tools/index.json` names the registry, declarations, permissions, and deed mappings.
