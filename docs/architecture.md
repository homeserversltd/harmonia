# Harmonia architecture

Harmonia is a Rust update manager and appliance-profile execution engine.

## Concept mapping

- Harmonia tool: one reusable Rust capability with one beautiful job, executable code, a manifest contract, and focused unit tests.
- Toolbelt: the code-owned set of Harmonia tools under `crates/harmonia/src/tools.rs`, reflected by `tools/<tool>/index.json` manifests for documentation and module wiring.
- Profile module need: profile module declares the tool it needs, then calls that toolbelt part to make the change.
- Harmonia profile spine: ordered modules for one installed body identity.
- Harmonia run ledger: `run.json`, `events.jsonl`, and per-step receipts.
- Harmonia tranche: a named command that checks, stages, promotes, or proves a profile transition.

## Toolbelt law

1. Adding a tool means adding Rust-owned tool code first.
2. Adding a tool also adds or updates `tools/<tool>/index.json` so modules can name the contract.
3. Configuration JSON wires existing tools and modules; it does not create tools by itself.
4. Each tool keeps singular purpose: one primitive, one receipt family, one unit-test seam.
5. Profile modules compose tools; modules do not hide bespoke mutation logic behind manifest data.

## Runtime ladder

1. Read local identity from installed config.
2. Fetch/update Harmonia source or release artifact.
3. Resolve exactly one profile.
4. Stage update payloads into an insulated work root.
5. Validate schema/profile/tool availability.
6. Execute ordered profile modules.
7. Promote only after proof.
8. Emit `run.json`, `events.jsonl`, and tool/module matrix.

## First profiles

- `homeserver`: replaces legacy updater behavior with receipt-backed Rust tools.
- `homeconsole`: HomeConsole and Arch Console as one profile family.
- `tv`: appliance update profile for TV bodies.

## First tool families

- `package`: OS package update/check/install primitive.
- `systemd`: unit install/enable/restart/status primitive.
- `files`: staged file/template/symlink primitive.
- `git-artifact`: branch/tag/artifact fetch primitive.
- `node-build`: npm/pnpm build primitive for web bodies.
- `receipt`: shared central receipt writer.

## Network testing posture

Harmonia should run first as insulated tests on LAN machines: copy binary + profile + fake root, run `plan-run`/dry-run, collect receipts, and only then promote profile-specific live mutation.
