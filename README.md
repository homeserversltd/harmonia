# Harmonia

Harmonia is a Rust update manager and appliance-profile execution engine for HOMESERVER bodies.

It is not a Python updater and not a shell orchestration lane. Shell is allowed only as a bootstrap doorway. Harmonia owns the update covenant in Rust: identity selection, profile graph resolution, staged execution, reusable tools, promotion, receipts, and installer integration.

## North Star

- One public update organism.
- One possessed identity/profile per installed body.
- Ordered profile spines instead of ambient discovery.
- A beautiful Rust toolbelt of specific tools, each singular in function and purpose.
- Profile modules call toolbelt parts to make changes; modules do not become hidden tool implementations.
- Adding a tool means adding executable Rust tool code, its manifest contract, and focused unit tests; configuration JSON alone is not a tool.
- No false green: every failed stage becomes a nonzero process exit and a receipt with `ok=false`.
- Atomic staging and promotion before mutation of live paths.
- Central run receipts: `events.jsonl`, `run.json`, and module/tool matrix.
- Installer-bundled technology: binary, config, state dirs, systemd service, systemd timer, and receipt roots.
- HomeConsole and Arch Console are one profile family.

## Repo-local command face

```text
./cli.py
./cli.py build
./cli.py install
sudo ./cli.py install --apply
./cli.py status
sudo ./cli.py uninstall --apply
```

`./cli.py` is the forward-facing Pythonic installer doorway. It exists so the Harmonia repo can teach and perform its own build/install/uninstall path without a private external helper. External orchestration may call this CLI, but the install contract lives here.

## Scaffold command

```text
cargo run -p harmonia -- explain
cargo run -p harmonia -- inspect-profile profiles/homeserver/index.json
cargo run -p harmonia -- plan-run profiles/homeconsole/index.json --receipt-dir /tmp/harmonia-receipts
```

`plan-run` is intentionally non-mutating in this first scaffold. It proves the spine/read/receipt shape before any machine receives a live update action.

## HomeConsole sync

`homeconsole-sync` bottles game-library sync as a Harmonia transition. Arcadia owns the Sync button/API surface; Harmonia owns the appliance-local command, provider configuration readback, adapter invocation, and redacted receipts.

```text
cargo run -p harmonia -- homeconsole-sync profiles/homeconsole/index.json --receipt-dir target/homeconsole-sync-check
cargo run -p harmonia -- homeconsole-sync profiles/homeconsole/index.json --apply --receipt-dir /var/lib/harmonia/receipts/homeconsole-sync-latest
```

The first module lives at `modules/homeconsole/sync/index.json`. It keeps sync inside Harmonia rather than a separate repo, wraps the proven `/usr/local/bin/arch-game-sync` singleton as the initial adapter, and reads optional provider credentials from `/etc/arch-game-sync/providers.env`. Receipts record provider names and missing env-key names only; secret values are never written.
