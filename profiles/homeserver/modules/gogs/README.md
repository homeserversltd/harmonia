# Gogs

## Role

Legacy Self-Hosted Git Service.

## Product purpose

Gogs represents the legacy git-host implementation in the HOMESERVER migration group. It remains a generic public service shape so Harmonia can select the live git host and retire the loser on each machine.

## Harmonia maintenance contract

This module represents package/runtime currentness, service health, and readiness proof for the legacy git-host competitor. Public source describes the service concern without private repositories, domains, or tokens.

## Public boundary

This public module describes reusable HOMESERVER product behavior. It does not contain credentials, tokens, passwords, private hostnames, private topology, or customer data. Runtime-specific values are supplied by installation and operations surfaces outside public source.

## Proof shape

A mature module proves its work with Harmonia receipts: selected profile, module id, operation count, changed state, health or readiness evidence, and `first_missing_signal=none` when the concern is current.
