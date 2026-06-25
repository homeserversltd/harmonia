# rust-build-toolchain

Harmonia maintains Rust toolchain parity for HOMESERVER appliances. Deployables seed this surface at birth; Harmonia keeps it present and proves it before Rust-built runtimes such as Coronatio, Caduceus, and Harmonia itself build or promote target-native binaries.

Required maintained surface:

- `/opt/rustup`
- `/opt/cargo`
- `/usr/local/bin/rustc`
- `/usr/local/bin/cargo`
- `/usr/local/bin/rustup`
- wrapper environment: `RUSTUP_HOME=/opt/rustup`, `CARGO_HOME=/opt/cargo`

The purpose is one appliance toolchain across states. Python remains a bootstrap/control doorway; Rust owns durable appliance behavior. A target-native Cargo build is the packaging boundary for Rust services.
