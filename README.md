# Harmonia

Harmonia is a Rust appliance update engine. Each invocation follows one bounded ritual: **ask → compare → do → attest**.

The engine has two authorization keys: diff-minted `Authorization` and the exact `--apply-or-timer` invocation key. A bare update may observe and report, but cannot perform a deed. Mutating behavior exists only in the twenty true-named transactional atoms under `src/atoms/do/`; each requires both keys by value and emits an attested result.

## Engine shape

- `src/atoms/ask/` performs bounded observations without mutation.
- `src/atoms/do/` contains the only mutation vocabulary.
- `src/atoms/attest/` redacts caller-injected secrets before serialization, appends the redacted `Receipt`, and forwards fields derived from that same redacted value.
- `src/tools/index.json` is the single tool registry. Its `declarations.records` contains exactly thirteen declaration records; `service-runtime` is a separate registry entry lowered to primitives, not one of those records.
- Ten bands run in charter order: `renew-self`, `pull-source`, `stage-profile`, `compare`, `install-packages`, `ratchet-binaries`, `restart-services`, `backfill-files`, `propose-edits`, `report-home`. `restart-services` precedes `backfill-files`.
- The closing census is zero: a successful run reports `first_missing_signal=none`.

Profiles provide ordered module declarations and constants. Modules compose the ritual and the registered tools; they do not create another mutation authority. Receipts are written for the run and its module/tool work.

## Repository map

```text
src/atoms/       ask, do, and attest ritual surfaces
src/bands/       ten charter-ordered execution bands
src/tools/       registered tool declarations and implementations
profiles/        selected profile and module declarations
installer/       installation support
docs/            architecture and engine notes
tests/           test guidance
```

## Safe development commands

```bash
cargo run -p harmonia -- --help
cargo run -p harmonia -- explain --help
cargo run -p harmonia -- toolbelt --help
cargo build --locked
```

Apply-capable commands require explicit authorization and are outside this documentation's read-only smoke examples.
