# ratchet-aur-package

`ratchet-aur-package` is a registered Harmonia tool declaration resolved through `src/tools/index.json`, the single registry. `ratchet-aur-package` is one of the thirteen deed declaration records in `src/tools/index.json`: permutation `build-pinned`, deed `install-aur-pinned`, permission `mutate`, and phases `observe → compare → act → attest`. It builds and installs the pinned AUR package through the keyed transactional do atom.

The two required mutation keys are diff-minted `Authorization` and the exact `--apply-or-timer` invocation key.
