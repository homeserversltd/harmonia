# Harmonia

Harmonia is a Rust update manager for appliance-style systems: home servers, game consoles, TV boxes, kiosks, and other machines that should update predictably without turning into a pile of one-off shell scripts.

It gives each machine one selected profile, runs that profile's ordered modules, calls focused Rust tools to make changes, and writes receipts that show exactly what happened. The result is an update path that can be tested, explained, repeated, installed, and audited.

## Why Harmonia exists

Most small appliance deployments start simple and then drift:

- one script updates packages;
- another script restarts services;
- a third script copies artifacts;
- a cron job runs without proof;
- nobody can tell whether the machine is current, skipped, or half-updated.

Harmonia replaces that pattern with a small public contract:

```text
profile -> ordered modules -> focused tools -> receipts
```

A profile says what this machine is. Modules say what work belongs to that profile. Tools do the actual work. Receipts prove the result.

## Design goals

- One public update engine.
- One selected profile per installed machine.
- Ordered profile modules instead of ambient discovery.
- A focused Rust toolbelt of specific tools, each with one purpose.
- Configuration manifests wire profiles and modules; they do not create tools by themselves.
- Failed work exits nonzero and records `ok=false`.
- Live paths are changed only after staging and proof.
- Every run leaves `events.jsonl`, `run.json`, and module/tool evidence.
- Installer-ready layout: binary, config, state directory, service, timer, and receipt root.

## Core concepts

### Profile

A profile is the machine's declared identity and update spine. A console, a server, and a TV appliance can each have different modules while using the same engine and toolbelt.

Example:

```text
profiles/homeconsole/index.json
```

### Module

A module is one ordered unit of profile work. It declares which tool it needs and the inputs for that tool.

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

A receipt is the audit trail for a run. Harmonia records what was checked, what changed, what was skipped, and why a run failed if it failed.

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
cargo run -p harmonia -- run-profile profiles/homeconsole/index.json \
  --module-root modules/homeconsole \
  --receipt-dir target/homeconsole-check
```

## Example: HomeConsole

The HomeConsole profile demonstrates the appliance pattern:

```text
identity          prove the machine context
system-packages   check/update Arch packages
game-library      protect active play sessions and sync game metadata
desktop-appliance manage the local console UI/runtime posture
pinned-artifacts  preserve known-good critical binaries
receipts          summarize run evidence
```

A full update command on an installed machine looks like this:

```bash
/usr/local/bin/harmonia homeconsole-update \
  /etc/harmonia/profiles/homeconsole/index.json \
  --apply \
  --receipt-dir /var/lib/harmonia/receipts/homeconsole-latest
```

A good run reports:

```text
ok=true
first_missing_signal=none
```

## Repository map

```text
cli.py                Repository-local build/install/status helper
crates/harmonia/      Rust engine and CLI
profiles/            Profile declarations
modules/             Profile module declarations
tools/               Tool manifest contracts
docs/                Architecture notes
installer/           Installation support
locks/               Known-good artifact locks
tests/               Test guidance
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
