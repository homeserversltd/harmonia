# Nginx

## Declared package authority

Every profile declares `package_authority` with an `os_family` and `package_manager`. Harmonia validates only supported pairs (`arch`/`pacman` and `debian`/`apt`) and selects package operations from that declaration, never from the host executable that happens to be present. Package receipts name the declared backend; dry runs use backend-native simulation and do not mutate packages.

## Nginx shared floor

The Nginx module now owns only the common floor: the package, a public comment-only shared site source, an explicitly owned `sites-enabled` link, `nginx -t` before link promotion, reload on an actual link change, and systemd readiness. It deliberately does not declare application virtual hosts, domains, upstreams, certificates, or secrets.

Secure Web Entry Point.

## Product purpose

Nginx is the public web entry point for a HOMESERVER appliance. It terminates secure access, routes service traffic, and makes local web services reachable through a controlled product boundary.

## Harmonia maintenance contract

This module represents virtual hosts, proxy policy, certificate handoff, reload behavior, and health proof. Public source describes reusable routing intent; site-specific domains and secrets stay outside the repository.

## Public boundary

This public module describes reusable HOMESERVER product behavior. It does not contain credentials, tokens, passwords, private hostnames, private topology, or customer data. Runtime-specific values are supplied by installation and operations surfaces outside public source.

## Proof shape

A mature module proves its work with Harmonia receipts: selected profile, module id, operation count, changed state, health or readiness evidence, and `first_missing_signal=none` when the concern is current.

## Product readiness

This README describes the product surface expected from the module. As implementation grows, the module should preserve this public contract while adding concrete Rust execution, sidecar constants, focused tests, and receipt checks. A module is complete only when the public concern is represented clearly and the update run can prove its current state.
