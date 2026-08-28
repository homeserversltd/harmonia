# Harmonia

Harmonia is a Rust appliance update engine. Each invocation follows one bounded ritual: **ask → compare → do → attest**.

## Engine shape

- Atoms are the engine floor. They host primitive operations and engines: comparison, command capture, AUR work, Git artifact work, systemd work, package work, declaration handling, and the embedded `declarations.json` authority.
- Tools compose those atom capabilities. The tool layer owns the managed-files dispatcher, ordered routines, virtual-environment work, household-time work, and artifact-lock compatibility work. Other tool paths are re-export seats for atom or tool implementations.
- Bands are the execution faces. A band calls tools, and tools call atoms. Bands do not call atoms directly, except `renew-self`, whose `replace_process` path is an intended direct atom exception.
- The `do` directory contains twenty true-named transactional atoms, one folder per atom. Mutating atoms require diff-minted `Authorization` and the exact `--apply-or-timer` invocation key.
- `src/atoms/attest/` redacts caller-injected secrets before serialization and forwards fields derived from the redacted value.

Profiles provide ordered module declarations and constants. Receipts are written for the run and its module and tool work.

## Repository map

```text
src/atoms/       primitive operations and the ask/do/attest surfaces
src/bands/       ten charter-ordered execution faces
src/tools/       composition tools and re-export seats
profiles/        selected profile and module declarations
installer/       installation support
docs/            architecture and engine notes
```


## Safe development commands

```bash
cargo run -p harmonia -- --help
cargo run -p harmonia -- explain --help
cargo run -p harmonia -- toolbelt --help
cargo build --locked
```

Apply-capable commands require explicit authorization and are outside this documentation's read-only smoke examples.
