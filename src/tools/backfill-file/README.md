# backfill-file

`backfill-file` is a registered Harmonia tool declaration resolved through `src/tools/index.json`, the single registry. `backfill-file` is one of the thirteen deed declaration records in `src/tools/index.json`: permutation `backfill`, deed `copy-file`, permission `mutate`, and phases `observe → compare → act → attest`. It backfills a declared file through the keyed transactional do atom.

The two required mutation keys are diff-minted `Authorization` and the exact `--apply-or-timer` invocation key.
