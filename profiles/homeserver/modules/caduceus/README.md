# Caduceus

## Role

Local Appliance Control.

## Product purpose

Caduceus provides the controlled local actuator for HOMESERVER status and update requests. It gives front-end and service surfaces one safe path to request convergence without exposing credentials or private topology in public source.

## Harmonia maintenance contract

This module owns the public service concern for the actuator: installed command, policy files, service unit, writable state surfaces, and receipt locations. Harmonia uses the module to keep the actuator aligned with the selected HOMESERVER profile.

## Public boundary

This public module describes reusable HOMESERVER product behavior. It does not contain credentials, tokens, passwords, private hostnames, private topology, or customer data. Runtime-specific values are supplied by installation and operations surfaces outside public source.

## Proof shape

A mature module proves its work with Harmonia receipts: selected profile, module id, operation count, changed state, health or readiness evidence, and `first_missing_signal=none` when the concern is current.

## Product readiness

This README describes the product surface expected from the module. As implementation grows, the module should preserve this public contract while adding concrete Rust execution, sidecar constants, focused tests, and receipt checks. A module is complete only when the public concern is represented clearly and the update run can prove its current state.
