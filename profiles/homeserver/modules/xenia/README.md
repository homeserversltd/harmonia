# Xenia

This homeserver module reads the public `appliance.xenia.v1` guest register and updates enabled, already-installed native process guests independently. The staff installs and removes guests; Harmonia refuses an absent guest and does not create its seat or unit. Own-service entries are skipped and clone entries are refused.

For entries with release candidates, the track walks the declared forge branch from newest commit to oldest. At each commit it selects the forge Release first, then the declared GitHub Release candidates in order, using the Release tagged `latest` only when its target matches that commit. A pinned SHA is checked directly. The selected source and candidate URL are recorded in the routine. A selected candidate binary must match the release flag and checksum before the existing seat is exchanged; the existing service restarts on changed bytes or a stale running identity, and health is read afterward.
