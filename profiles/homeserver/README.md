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
- `matrix` defines the private Synapse chat service and its Element Web client surface.
- `tailscale` defines private network access as a product capability.
- `samba` defines LAN file sharing.
- `systemd` owns HOMESERVER systemd unit and mount management. Every reusable unit template lives directly in `profiles/homeserver/modules/systemd/`; Harmonia treats those files as the desired unit set for `/etc/systemd/system/`.
- `udev` owns HOMESERVER UDEV rule management. Every reusable HOMESERVER UDEV rule lives directly in `profiles/homeserver/modules/udev/`; Harmonia treats those files as the desired rule set for `/etc/udev/rules.d/`.
- Application modules describe the public service concerns Harmonia will maintain as they graduate into executable modules.



## Self-contained module intent

Every HOMESERVER module is a self-contained intent that must remain updated. The module owns the desired state for its appliance concern, the installed surfaces that express that state, the comparison that proves drift, the safe mutation sequence, the domain-specific reconcile step, and the receipt that proves the concern current.

For managed-file modules, Harmonia renders the desired file from the module, reads the installed target, compares desired bytes to installed bytes, writes only when drift exists, applies declared metadata, runs the domain reconcile step, and records per-file plus aggregate receipts. UDEV reloads UDEV rules when rule files change. Systemd runs daemon-reload when unit files change and then reconciles declared unit state.

## Managed file update contract

Harmonia managed-file modules own both the desired files and the update rule for those files. For the HOMESERVER UDEV module, the module directory is the complete public desired state: each `*.rules.tmpl` file in `profiles/homeserver/modules/udev/` renders to a rule in `/etc/udev/rules.d/`.

A UDEV update is not a blind copy. Harmonia renders the desired file, reads the current target file, compares the rendered bytes to the installed bytes, and writes only when the desired content differs. A changed file is written through a temporary target, promoted into place, assigned the declared mode and ownership, and followed by a UDEV rule reload. The receipt records every rule considered, whether it changed, the target path, the reload decision, and the first missing signal if the module cannot close.

This same managed-file pattern applies to other HOMESERVER module files: the module owns the desired content, Harmonia compares desired state to installed state, and updates are performed only when the comparison proves drift.

## Rust toolchain parity

HOMESERVER appliances require one maintained Rust toolchain contract across deployment, Harmonia updates, and live runtime repair. The profile module `rust-build-toolchain` maintains `/opt/rustup`, `/opt/cargo`, and `/usr/local/bin/{rustc,cargo,rustup}` wrappers that export `RUSTUP_HOME=/opt/rustup` and `CARGO_HOME=/opt/cargo`.

Target-native Rust builds make appliance promotion predictable. Packaging problems collapse into the maintained Python bootstrap/control doorway plus the Harmonia Rust toolchain contract instead of per-host binary improvisation.

## Public boundary

This profile is safe for public source. It contains reusable product module concerns and non-secret public configuration only. Runtime credentials, keys, tokens, passwords, customer data, host identities, and site-specific values are supplied outside public source.

## Receipts

A successful HOMESERVER Harmonia run reports the selected profile, the modules that ran, whether anything changed, and the first missing signal if the profile could not close. The desired healthy state is `ok=true` with `first_missing_signal=none`.

## Company standard

HOMESERVERSLTD public repositories should read as professional product engineering material. The HOMESERVER profile documents the appliance product, its maintainable service concerns, and the proof Harmonia produces. Public copy must be useful to engineers evaluating the repository and must never reduce a module to placeholder text.
