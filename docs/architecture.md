# Harmonia architecture

Harmonia is a Rust update manager for machines that should behave like appliances: predictable identity, ordered updates, explicit safety checks, and readable proof after every run.

## Runtime model

```text
profile -> Rust-registered modules -> manifest-declared tool sequence -> tools -> receipts
```

- A **profile** declares what kind of machine is being updated.
- A **module** is a Rust-owned capability boundary that registers and validates one ordered part of that profile's update plan.
- A **module manifest** declares the ordered tool calls, defaults, and inputs for that registered module.
- A **tool** performs one focused action in Rust.
- A **receipt** records the result.

This structure keeps public behavior easy to explain and easy to test. Configuration describes the plan for registered code-owned modules; Rust modules and tools own the actions.

## Concept mapping

- Harmonia tool: one reusable Rust capability with one focused job, executable code, a manifest contract, and focused unit tests.
- Toolbelt: the code-owned set of Harmonia tools under `crates/harmonia/src/tools.rs`, reflected by `tools/<tool>/index.json` manifests for documentation and module wiring.
- Profile module: a Rust-registered capability boundary that validates its manifest contract before it calls toolbelt parts to make the change.
- Profile spine: the ordered module list for one installed machine identity.
- Run ledger: `run.json`, `events.jsonl`, and per-step receipts.
- Transition command: a named command that checks, stages, promotes, or proves a profile transition.

## Toolbelt law

1. Adding a tool means adding Rust-owned tool code first.
2. Adding a tool also adds or updates `tools/<tool>/index.json` so modules can name the contract.
3. Configuration JSON wires existing tools and modules; it does not create tools by itself.
4. Each tool keeps singular purpose: one primitive, one receipt family, one unit-test seam.
5. Profile modules are Rust-registered capability boundaries; manifests declare the ordered tool sequence for the registered module.
6. Modules compose tools; modules do not hide bespoke mutation logic behind manifest data.
7. Placeholder acknowledgement modules are not valid Harmonia modules: no empty modules, no `ack` placeholders that only manufacture green, no JSON `steps[]` ladder, no literal no-op command guards, and no profile references to missing module trees.

## Runtime ladder

1. Read local identity from installed config.
2. Resolve exactly one profile.
3. Validate schema, module availability, and tool availability.
4. Stage payloads into an insulated work root when mutation is needed.
5. Execute ordered profile modules.
6. Promote staged changes only after proof.
7. Emit `run.json`, `events.jsonl`, and tool/module evidence.
8. Exit with a clear success or failure state.

## Current profile family

- `homeconsole`: HomeConsole and Arch Console appliance profile family.

Future profile families such as `homeserver` and `tv` enter only with Rust-registered module boundaries and proof.

## First tool families

- `package`: OS package update/check/install primitive.
- `systemd`: unit install/enable/restart/status primitive.
- `files`: staged file/template/symlink primitive.
- `git-artifact`: branch/tag/artifact fetch primitive.
- `node-build`: npm/pnpm build primitive for web bodies.
- `receipt`: shared central receipt writer.

## Test posture

Harmonia work should prove the safe path first: run a dry profile check, collect receipts under `target/`, then run an applying command only when the receipt shape is understood.
