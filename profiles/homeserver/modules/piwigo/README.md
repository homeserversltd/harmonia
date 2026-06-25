# Piwigo

## Role

Photo Library Service.

## Product purpose

Piwigo provides photo library publishing and browsing. It is maintained as a web service with database, file storage, and health concerns.

## Harmonia maintenance contract

This module represents runtime currentness, data persistence, database linkage, web reachability, and proof. Public source defines reusable maintenance intent, not private albums or credentials.

## Public boundary

This public module describes reusable HOMESERVER product behavior. It does not contain credentials, tokens, passwords, private hostnames, private topology, or customer data. Runtime-specific values are supplied by installation and operations surfaces outside public source.

## Proof shape

A mature module proves its work with Harmonia receipts: selected profile, module id, operation count, changed state, health or readiness evidence, and `first_missing_signal=none` when the concern is current.

## Product readiness

This README describes the product surface expected from the module. As implementation grows, the module should preserve this public contract while adding concrete Rust execution, sidecar constants, focused tests, and receipt checks. A module is complete only when the public concern is represented clearly and the update run can prove its current state.
