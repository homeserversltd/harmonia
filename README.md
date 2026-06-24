# Harmonia

Harmonia is a Rust update manager for appliance-style systems: home servers, game consoles, TV boxes, kiosks, and other machines that should update predictably without turning into a pile of one-off shell scripts.

It gives each machine one selected profile, runs that profile's ordered Rust module spine, calls focused Rust tools to make changes, writes per-run receipts, and appends each module result to one profile ledger. The result is an update path that can be tested, explained, repeated, installed, and historically audited.

## Why Harmonia exists

Most small appliance deployments start simple and then drift:

- one script updates packages;
- another script restarts services;
- a third script copies artifacts;
- a cron job runs without proof;
- nobody can tell whether the machine is current, skipped, or half-updated.

Harmonia replaces that pattern with a small public contract:

```text
profile -> ordered modules -> focused tools -> one profile ledger + receipts
```

A profile says what this machine is. Profile-adjacent Rust modules own the ladder logic for that profile. Sidecars carry constants only. Tools do the actual primitive work. One append-only profile ledger records historical continuity, while per-run receipts prove the local run.

## Design goals

- One public update engine.
- One selected profile per installed machine.
- Ordered profile modules with Rust-owned validation/execution instead of ambient discovery or JSON-only placeholders.
- A focused Rust toolbelt of specific tools, each with one purpose.
- Sidecars provide constants only; they do not create modules, tools, ladders, or commands by themselves.
- Failed work exits nonzero and records `ok=false`.
- Live paths are changed only after staging and proof.
- Every run leaves `events.jsonl`, `run.json`, and module/tool evidence.
- Every module result appends to exactly one JSONL profile ledger under the receipts root, such as `homeconsole-ledger.jsonl`.
- Installer-ready layout: binary, config, state directory, service, timer, and receipt root.

## Core concepts

### Profile

A profile is the machine's declared identity and update spine. A console, a server, and a TV appliance can each have different modules while using the same engine and toolbelt.

Example:

```text
profiles/homeconsole/index.json
```

### Module

A module is one ordered unit of profile work. The module boundary is validated and executed in Rust; its adjacent sidecar supplies constants only.

Example module work:

- prove machine identity;
- check or update OS packages;
- stage and promote an application artifact;
- restart and verify a service;
- write a receipt summary.

### Tool

A tool is executable Rust behavior with one clear purpose. Adding a tool means adding code, a manifest contract, and tests for that tool's seam.

Examples:

- `package` checks or applies operating-system packages;
- `systemd` manages service state;
- `artifact` promotes a binary or release payload;
- `health` verifies readiness;
- `receipt` writes run evidence.

### Receipt

A receipt is the audit trail for a run. The profile ledger is the historical continuity trail across runs. Harmonia records one JSONL ledger entry per module with `sequence`, `stamped_at_unix_ms`, `run_id`, profile identity, module id, pass/fail, changed state, operation count, and first missing signal.

## Quick start

Use the repo-local command face for install-oriented operations:

```bash
./cli.py
./cli.py build
./cli.py install
sudo ./cli.py install --apply
./cli.py status
sudo ./cli.py uninstall --apply
```

Use Cargo while developing the Rust engine:

```bash
cargo run -p harmonia -- explain
cargo run -p harmonia -- toolbelt
cargo run -p harmonia -- inspect-profile profiles/homeconsole/index.json
cargo test -p harmonia
```

Run a non-mutating profile check and write receipts:

```bash
cargo run -p harmonia -- homeconsole-update profiles/homeconsole/index.json --receipt-dir target/homeconsole-check
```

## Example: HomeConsole

The HomeConsole profile demonstrates the appliance pattern:

```text
identity                  prove the machine context
system-packages           check/update Arch packages
harmonia-runtime          prove the installed Harmonia binary and profile are possessed
keyman-runtime            refresh the Keyman git checkout and install its runtime payload
homeconsole-sync-runtime  refresh the standalone sync git checkout and run its installer
rust-build-toolchain      maintain the Rust toolchain needed for source-built runtimes
arcadia-gui-runtime       sync, build, promote, restart, and health-prove Arcadia GUI
pinned-artifacts-runtime  check blessed known-good artifacts against the lock
```

A full update command on an installed machine looks like this:

```bash
/usr/local/bin/harmonia homeconsole-update \
  /etc/harmonia/profiles/homeconsole/index.json \
  --apply \
  --receipt-dir /var/lib/harmonia/receipts/homeconsole-update-latest
```

A good run reports:

```text
ok=true
first_missing_signal=none
```

## Repository map

```text
cli.py                Repository-local build/install/status helper
src/                  Rust engine, thin dispatch/profile/receipt surfaces, and one src/tools toolbelt
profiles/             Profile declarations with adjacent constants-only module sidecars
docs/                 Architecture notes
installer/            Installation support
locks/                Known-good artifact locks
tests/                Test guidance
```

## Public contract

Harmonia is intentionally small at the boundary:

1. declare the machine profile;
2. run ordered modules;
3. call focused Rust tools;
4. stage before promotion;
5. write receipts;
6. exit clearly.

That is the product: reliable appliance updates with visible proof.

## HomeConsole Sync Runtime

Harmonia keeps `git@git.home.arpa:HOMESERVERSLTD/homeconsole-sync.git` current at `/opt/homeconsole-sync/source` and installs `/usr/local/bin/homeconsole-sync`; the `homeconsole-sync` transition invokes that runtime and records redacted receipts.
