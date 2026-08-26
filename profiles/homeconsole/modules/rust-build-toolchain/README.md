# Rust Build Toolchain

## Role

Target-native Rust build environment for HomeConsole.

## Product purpose

HomeConsole includes Rust-built services and appliance components. The appliance needs a maintained toolchain so those services can be built, promoted, and repaired on the target body with the same environment every time.

## Maintained surface

- `/opt/rustup` (mode `0755`, owner:group `owner:owner`)
- `/opt/cargo` (mode `0755`, owner:group `owner:owner`)
- `/usr/local/bin/rustc`
- `/usr/local/bin/cargo`
- `/usr/local/bin/rustup`
- wrapper environment: `RUSTUP_HOME=/opt/rustup`, `CARGO_HOME=/opt/cargo`

## Harmonia maintenance contract

Harmonia maintains the HomeConsole Rust build toolchain before Rust-built runtimes and appliance components build or promote target-native binaries. The owner build-bearer is the accountable bearer for this maintained build surface; Python remains a bootstrap and control doorway while Rust owns durable appliance behavior.

## Public boundary

This public module describes reusable HomeConsole product behavior. It does not contain credentials, tokens, passwords, private hostnames, private topology, or customer data.

## Proof shape

A mature run proves that root resolves the `/usr/local/bin` wrappers, the wrapper environment points at `/opt/rustup` and `/opt/cargo`, and target-native Cargo builds pass before binary promotion. An empty diff is a successful quiet convergence: no movement is required.
