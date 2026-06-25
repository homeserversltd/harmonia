# MkDocs

## Role

Documentation Publishing.

## Product purpose

MkDocs publishes HOMESERVER documentation as a maintained service surface. Documentation publication is part of the appliance product, not a manual afterthought.

## Harmonia maintenance contract

This module represents source/build/promote behavior, service readiness, and receipt-backed proof. Harmonia will use it to keep documentation current through the same profile mechanism as other services.

## Public boundary

This public module describes reusable HOMESERVER product behavior. It does not contain credentials, tokens, passwords, private hostnames, private topology, or customer data. Runtime-specific values are supplied by installation and operations surfaces outside public source.

## Proof shape

A mature module proves its work with Harmonia receipts: selected profile, module id, operation count, changed state, health or readiness evidence, and `first_missing_signal=none` when the concern is current.

## Product readiness

This README describes the product surface expected from the module. As implementation grows, the module should preserve this public contract while adding concrete Rust execution, sidecar constants, focused tests, and receipt checks. A module is complete only when the public concern is represented clearly and the update run can prove its current state.
