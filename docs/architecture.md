# Harmonia architecture — engine restructure

Harmonia breathes through one bounded engine path: **ask → compare → do → attest**. The path is typed, profile-scoped, and quiet when current. It does not block on remote observers, and it does not invent authorization from drift alone.

## Current engine (pre-migration)


Harmonia updates through one lane:

Profile -> Identity -> literal Rust module logic + adjacent sidecar constants -> shared Rust tools -> receipt.

HomeConsole is the sole console identity. The HomeConsole profile is `profiles/homeconsole/index.json`; module-specific Rust logic and constants live together under `profiles/homeconsole/modules/<module>/index.rs` and `sidecar.json`. `src/module_dispatch.rs` is only the thin loader/dispatcher, and shared capability primitives live under `src/tools/*.rs`.

Sidecars are constants only: paths, repos, branches, packages, services, users, groups, modes, URLs, health endpoints, locks, state files, env file paths, and expected receipt families. Sidecars do not own sequencing, commands, ladders, recursive Harmonia invocation, or appliance identity.

Historical continuity is one ledger per profile, stored as JSONL under the receipts root, for example `homeconsole-ledger.jsonl`. Each module appends exactly one pass/fail entry per run with a stamp, sequence, run id, profile identity, module id, operation count, changed state, and first missing signal. Harmonia does not create per-module ledgers.

## Self-contained module currentness

A Harmonia module is a self-contained intent that must remain updated. The module owns the desired state for one appliance concern, the target surfaces that express that concern on the live body, the comparison that decides whether the concern is current, the safe mutation sequence that repairs drift, the domain-specific reconcile step, and the receipt schema that proves closure.

Shared tools provide primitives: file comparison, atomic promotion, command execution, package checks, systemd operations, health probes, and receipt writing. A tool does not decide what the appliance concern means. The module composes the tools in the lawful order for its own domain.

Managed-file modules follow the same update skeleton: render desired content from module-owned source, read the installed target, compare bytes and declared metadata, write only when drift exists, promote atomically, set ownership and mode, run the domain reconcile step, then receipt each file and the aggregate module. UDEV reconciles by reloading UDEV rules. Systemd reload and restart are gated by material changed during this run: a binary swap or a changed file declared by that module. Unchanged service material produces `converged-quiet` and no mutating systemd command. There is no force or manifest exception to the gate. Nginx validates with `nginx -t` before a change-driven reload. Firewall validates and applies its ruleset only when its declared material changed. Every module remains one intent with its own currentness definition.


## Target tree

```text
main/
├── bands/
│   ├── renew-self/
│   ├── pull-source/
│   ├── stage-profile/
│   │   ├── molt/
│   │   └── capsule/
│   │       └── prior-capsule-rollback-seat/
│   ├── compare/
│   ├── install-packages/
│   ├── ratchet-binaries/
│   ├── restart-services/
│   ├── backfill-files/
│   ├── propose-edits/
│   └── report-home/
├── tools/
│   └── index.json
├── atoms/
│   ├── ask/
│   ├── do/
│   └── attest/
├── profiles/
│   └── <id>/
│       ├── locks/
│       └── tests/
└── migration/
    └── slice-1/
```

## Two keys

The engine has two keys: diff-minted **Authorization** and invocation key **`--apply-or-timer`**. Do requires both by value; a bare `update` observes all and performs no act. Attest is one custody call: append the receipt to the appliance log stream, then forward through Hyalos using the same redacted receipt.

## Charter target — ten bands

Install-package is the nested package-install half: it observes pacman with `-Q`, compares through the shared gate, acts only through the keyed package atom, preserves the legacy pacman retry/receipt behavior, and appends report-home attestations to a separate `<name>.attest.jsonl` appliance log rather than the legacy JSON receipt.

The exact ordered bands are: **renew-self; pull-source; stage-profile (containing molt + capsule and one retained prior capsule as rollback seat); compare; install-packages; ratchet-binaries (three-of-a-kind atomic); restart-services; backfill-files; propose-edits; report-home.**

## Tool species law and registry

Tools are single-act tools only. The current pre-migration registry is the `src/tools.rs` `TOOLBELT`, whose shelf entries are: `ai-coding-harness`, `artifact-lock`, `aur`, `command`, `files`, `git-artifact`, `health`, `household-time`, `package`, `service-runtime`, `systemd`, and `venv`. The target charter makes `src/tools/index.json` the ONE registry; the shelf list stays. Compounds are routines in module manifests, never new tool species.

## Rung composition

Observe is **ask + attest**. Act is **do + attest**. `report-home` is **attest alone**. Stdlib world-touching occurs only inside atoms; no-block is mandatory. Bare `update` observes all and performs no act. Acting requires both diff-minted `Authorization` and invocation key **`--apply-or-timer`**.

## Drift and proposals

`on_drift` is typed. Absent means **Hold**: the user file wins, the ledger gets a quiet line, and known-good is sealed in the capsule. **Propose** emits one interactable with a human ceiling. **Replace** is allowed only_if_exact the sha256 of known-bad matches, and lowers the change to the hotfix lane whose predicates grow `FileMatchesExactly`; a missing propose-file is birth's debt.

Proposals seat at `/var/lib/harmonia/proposals/` and have one identity across CLI and GUI. `show-known-good` is an ask-only face verb. Locks are exactly `profiles/<id>/locks/`. Tests are reserved until the operator's word. The heir wears identical geometry.

## Migration status

`make-symlink` carries an act-purity debt from slice 4: its act rung still reads only transaction-owned staging candidates during cleanup/restaging; a later slice will replace those checks with mutation-return state without weakening rollback correctness.

Slice 8 lands `set-clock` and `check-health`. `set-clock` observes the current timezone and time-synchronization facts through `atoms::ask`; only a nonempty comparison grants both keys to its `atoms::do` act rung, and the legacy `household-time` interface and receipt writer remain authoritative. `check-health` is the first chartered no-act tool: its directory contains only `observe` and `report-home`, its bounded retry/content probe runs through `atoms::ask`, and the legacy health command receipt remains authoritative.

Slice 9 lands build-venv and build-crate nested organs. build-venv preserves the harmonia.venv.converge.v1 receipt oracle and build-crate owns the keyed cargo-build breath; service-runtime cargo build delegation is landed while broader routine-ization remains pending. Slices 1–9 are landed. Pull-repo plan/apply delegate through observe/compare/act, while source acquisition does the same and retains `git_artifact::legacy_acquire_source` only behind the keyed atom fallback. The bounded pull-repo report-home debt remains: public `SourceOutcome`/`Outcome` carry no receipt-log path, so the legacy caller receipt writer remains authority; no fabricated local attestation is emitted.  The atoms floor and one data registry stand; `place-file` owns each `files/converge` single-file breath; `remove-file` owns the `files/remove` observe-compare-remove breath; and the validated-file-symlink exemplar is absorbed by its chartered `make-symlink` seat. `enable-unit` and `remove-unit` own delegated systemd breaths while the legacy systemd receipt schema and fields remain writer authority. Named small atom permutations are the timeout/scoped systemd state query and scoped typed `EnableNow`/`DisableNow`. Both new seats observe through `atoms::ask`, mutate only through `atoms::do` after the comparison gate grants both keys, and report home without changing established receipt schemas. `backfill-file` owns hotfix file placement through nested observe/act/report-home; `hotfix.rs` delegates placement to it, and `FileMatchesExactly` lowers Replace only when the declared known-bad sha256 matches. `files.rs` retains declaration production, its public removal interface, aggregate accounting, and ladder behavior while delegating removal execution. Hotfix backfill, all remaining bands, tools, and profile migration remain flat or at the registry status declared for their current shelf entries. No-block breath.
