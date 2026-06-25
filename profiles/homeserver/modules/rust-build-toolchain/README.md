# Rust Build Toolchain

## Role

Target-native Rust build environment.

## Product purpose

HOMESERVER includes Rust-built services. The appliance needs a maintained toolchain so those services can be built, promoted, and repaired on the target body with the same environment every time.

## Maintained surface

- `/opt/rustup`
- `/opt/cargo`
- `/usr/local/bin/rustc`
- `/usr/local/bin/cargo`
- `/usr/local/bin/rustup`
- wrapper environment: `RUSTUP_HOME=/opt/rustup`, `CARGO_HOME=/opt/cargo`

## Harmonia maintenance contract

Harmonia maintains Rust toolchain parity before Rust-built runtimes such as Coronatio, Caduceus, and Harmonia itself build or promote target-native binaries. Python remains a bootstrap and control doorway; Rust owns durable appliance behavior.

## Public boundary

This public module describes reusable HOMESERVER product behavior. It does not contain credentials, tokens, passwords, private hostnames, private topology, or customer data.

## Proof shape

A mature run proves that root resolves the `/usr/local/bin` wrappers, the wrapper environment points at `/opt/rustup` and `/opt/cargo`, and target-native Cargo builds pass before binary promotion.
