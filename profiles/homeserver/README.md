# HOMESERVER profile

HOMESERVER is the public Harmonia profile for maintaining a HOMESERVERSLTD self-hosted appliance as a coherent product. It defines the reusable service, network, system integration, media, storage, search, toolchain, and control concerns that the appliance needs in order to stay current.

Harmonia is a Rust appliance update manager. It keeps a selected appliance profile current by running ordered modules, applying safe configuration, and writing receipts that prove what changed and what still needs attention.

## Product model

A profile names one appliance identity and the modules that maintain it. Each folder under `modules/` names one product concern. Some modules already contain executable Rust update logic. Some modules currently contain public configuration or product documentation that becomes executable as the HOMESERVER profile matures. Public source carries reusable product truth only.

## Current executable modules

- `rust-build-toolchain` maintains the Rust build environment used for target-native service builds.
- `coronatio` maintains the HOMESERVER crown service runtime.
- `caduceus` maintains the local appliance control lever used to request safe convergence.

## Represented product concerns

- `nginx` defines the secure web entry point.
- `firewall` defines network exposure boundaries.
- `postgres` defines the shared database service concern.
- `tailscale` defines private network access as a product capability.
- `samba` defines LAN file sharing.
- `systemd` carries public unit and mount templates used by deployment and update flows.
- `udev` carries the public RAPL telemetry permission rule used by deployment and update flows.
- Application modules describe the public service concerns Harmonia will maintain as they graduate into executable modules.

## Rust toolchain parity

HOMESERVER appliances require one maintained Rust toolchain contract across deployment, Harmonia updates, and live runtime repair. The profile module `rust-build-toolchain` maintains `/opt/rustup`, `/opt/cargo`, and `/usr/local/bin/{rustc,cargo,rustup}` wrappers that export `RUSTUP_HOME=/opt/rustup` and `CARGO_HOME=/opt/cargo`.

Target-native Rust builds make appliance promotion predictable. Packaging problems collapse into the maintained Python bootstrap/control doorway plus the Harmonia Rust toolchain contract instead of per-host binary improvisation.

## Public boundary

This profile is safe for public source. It contains reusable product module concerns and non-secret public configuration only. Runtime credentials, keys, tokens, passwords, customer data, host identities, and site-specific values are supplied outside public source.

## Receipts

A successful HOMESERVER Harmonia run reports the selected profile, the modules that ran, whether anything changed, and the first missing signal if the profile could not close. The desired healthy state is `ok=true` with `first_missing_signal=none`.

## Company standard

HOMESERVERSLTD public repositories should read as professional product engineering material. The HOMESERVER profile documents the appliance product, its maintainable service concerns, and the proof Harmonia produces. Public copy must be useful to engineers evaluating the repository and must never reduce a module to placeholder text.
