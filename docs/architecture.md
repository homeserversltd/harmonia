# Harmonia architecture

Harmonia is a Rust Chrysalis dedicated to updates.

## Concept mapping

- Chrysalis tool -> Harmonia Rust tool.
- Deployable module need -> profile module declares the tool it needs.
- Chrysalis phase spine -> Harmonia profile spine.
- Central Chrysalis logger -> Harmonia run ledger.
- Module pulsation -> Harmonia `pulse-tool` / `plan-run` tranche.

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

- `homeserver`: mines current homeserver updater quarry and replaces it with receipt-backed Rust tools.
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
