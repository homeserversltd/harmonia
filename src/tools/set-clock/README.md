# set-clock

`set-clock` is a registered Harmonia tool declaration resolved through `src/tools/index.json`, the single registry. `set-clock` is one of the thirteen deed declaration records in `src/tools/index.json`: permutation `set`, deed `set-clock`, permission `mutate`, and phases `observe → compare → act → attest`. It sets the declared clock state through the keyed transactional do atom.

The two required mutation keys are diff-minted `Authorization` and the exact `--apply-or-timer` invocation key.
