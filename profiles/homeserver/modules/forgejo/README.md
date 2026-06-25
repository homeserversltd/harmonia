# Forgejo

## Role

Self-Hosted Git Service.

## Product purpose

Forgejo provides the HOMESERVER Git service. It is maintained as durable collaboration infrastructure with repository data, service health, and web access boundaries.

## Harmonia maintenance contract

This module represents runtime currentness, service installation, repository data boundaries, backup implications, and readiness proof. Public source describes the service concern without private repositories or tokens.

## Public boundary

This public module describes reusable HOMESERVER product behavior. It does not contain credentials, tokens, passwords, private hostnames, private topology, or customer data. Runtime-specific values are supplied by installation and operations surfaces outside public source.

## Proof shape

A mature module proves its work with Harmonia receipts: selected profile, module id, operation count, changed state, health or readiness evidence, and `first_missing_signal=none` when the concern is current.

## Product readiness

This README describes the product surface expected from the module. As implementation grows, the module should preserve this public contract while adding concrete Rust execution, sidecar constants, focused tests, and receipt checks. A module is complete only when the public concern is represented clearly and the update run can prove its current state.
