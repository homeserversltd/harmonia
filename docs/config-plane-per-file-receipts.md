# ConfigPlane per-file receipts

A `harmonia.run_profile.v1` receipt adds each typed managed-file ConfigPlane
witness to `config_surfaces`. The record schema is
`harmonia.config_plane_witness.v1` and carries `path`, `module_id`, `category`,
and `disposition`. Category remains the declaration (`known-good` or
`interactable`); disposition records this run's observation and is not a
category rewrite.

The closed disposition vocabulary is:

- `converged`: a known-good declaration matches its observed ConfigPlane target;
- `interactable-offered`: drift was recognized and presented without writing
  the ConfigPlane target;
- `interactable-converged`: an interactable declaration is already converged;
- `refused-unrecognized`: an observed target's recognition score was below the
  interactable threshold;
- `interactable-exempt`: the declared suppression policy exempted the surface.

An absent managed target fails with the named
`managed-file-target-absent:<path>` signal. It has no ConfigPlane disposition
and is not `refused-unrecognized`. An unreadable observation likewise fails
at the observation boundary and does not receive an invented typed disposition.
An omitted managed-file category resolves to `known-good`, matching validation's
default.

For managed-files entries, a known-good ConfigPlane file with drift remains on
the proposal path. This includes targets under `/home/owner`: their observed
bytes determine whether the witness says `converged` or records a proposal or
refusal disposition. The ConfigPlane target is never written by this
witness path. Existing
`config-state-*.json` and proposal feed sidecars remain in their existing
locations. A legacy config-state sidecar whose `target` matches a typed witness
`path` is nested verbatim in that witness's `legacy_config_state_evidence`
array, avoiding a duplicate `config_surfaces` record. Unmatched legacy sidecars
remain standalone records. Raw sidecar fields, including unknown additions, are
preserved, and both standalone and typed projections use deterministic ordering.

For emitted typed witnesses, the central `managed-files.attest.jsonl` line and
best-effort Hyalos `attributes_redacted` object carry `schema`, `path`,
`module_id`, `category`, and `disposition` as structural fields. An absent-target
failure carries its named signal without a typed disposition. A per-module
`config-plane-witnesses.jsonl` supplies the typed records to the root receipt
collector; collection and run-start cleanup walk at most eight directory levels
below each direct `modules/<module_id>` directory, skip symlink directories,
and read/remove only exact regular-file witness logs. Identical typed witnesses
are emitted once per run while raw witness fields, including unknown additions,
are preserved.

This contract is deliberately limited to `managed-files` entries with a
resolved ConfigPlane target and a recognized declared category. It does not
infer a category or create witnesses for other file/converge permutations,
compiled fragments, or arbitrary ConfigPlane paths lacking that managed-file
category declaration. Those surfaces require a separate contract rather than a
manifest grammar expansion here.
