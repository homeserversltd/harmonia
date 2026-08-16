# build-crate

`build-crate` is a registered Harmonia tool declaration resolved through `src/tools/index.json`, the single registry. `build-crate` is one of the thirteen deed declaration records in `src/tools/index.json`: permutation `build`, deed `build-crate`, permission `mutate`, and phases `observe → compare → act → attest`. It builds the declared crate through the keyed transactional do atom.

The two required mutation keys are diff-minted `Authorization` and the exact `--apply-or-timer` invocation key.
