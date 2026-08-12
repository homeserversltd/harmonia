# Harmonia architecture — engine restructure

Harmonia breathes through one bounded engine path: **ask → do → attest**. The
path is typed, profile-scoped, and quiet when current. It does not block on
remote observers, and it does not invent authorization from drift alone.

## Target tree

```text
main/
├── bands/
├── tools/
└── atoms/
    ├── ask/
    ├── do/
    └── attest/
```

This slice lands the atoms floor under `src/atoms/` and reserves the profile
locks, tests, reserve, monad, and migration surfaces for their named follow-on
work. Each atom has an `index.rs`, `index.json`, and `README.md`.

## Two keys

The engine has two keys: **observation** and **authorization**. Ask produces
structured observations and typed drift: file bytes plus SHA-256, a read-only
command result, unit state, or an HTTP probe. `Drift` is explicit rather than
a stringly status.

Do is the only mutating lane. Its private-constructor authorization is minted
by the comparison gate and consumed **by value**, so an empty comparison cannot
reach mutation. File writes are backup-first. Commands and unit changes are
represented as mutating operations behind the same gate.

Attest is one custody call: append the receipt to the appliance log stream,
then forward through Hyalos using the existing redaction hook. Credentials,
keys, and dotfiles are not an atom surface.

## Breath law

Every future band or profile composes these atoms without changing their
ordering: observe without blocking, compare typed drift, mutate only with
by-value authorization, and attest once. The landed slice is deliberately
small; it establishes the floor without adding tests or new controls.
