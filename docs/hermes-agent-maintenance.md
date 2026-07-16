# Hermes Agent maintenance tool

`hermes-agent-maintenance` is the public Harmonia payload for maintaining one selected Hermes Agent installation on Linux.

The tool deliberately carries no machine schedule, username, home path, profile selection, or private endpoint. A selecting Harmonia profile installs and schedules it.

## Run contract

One invocation:

1. acquires a nonblocking process lock;
2. records the installed Hermes version;
3. runs `hermes update --check` for the selected profile;
4. applies an available update with `hermes update --yes`;
5. leaves the existing gateway untouched if the check or update fails;
6. applies the declared gateway lifecycle: it restarts and proves the selected profile's dedicated unit, restarts and proves the default unit when `multiplex-default` is declared, or performs no gateway action when `none` is declared;
7. for gateway-owning modes, proves the unit active and requires healthy `hermes gateway status` semantics;
8. atomically replaces `latest.json` with the run receipt.

A current installation still receives the scheduled gateway restart in gateway-owning modes. In `none` mode, a current installation produces a green `current-no-gateway` receipt without a restart. Overlapping invocations write `last-skipped-locked.json` without replacing the active run's `latest.json` receipt.

## Profile policy

The selecting profile may set:

- `HERMES_MAINTENANCE_PROFILE` — `default` or a named Hermes profile;
- `HERMES_MAINTENANCE_HERMES_BIN` — Hermes CLI path;
- `HERMES_MAINTENANCE_GATEWAY_MODE` — `dedicated` (default), `multiplex-default`, or `none`. `none` is for bodies that maintain a Hermes installation but do not own or declare any gateway lifecycle;
- `HERMES_MAINTENANCE_GATEWAY_UNIT` — optional assertion that must equal the unit implied by a gateway-owning mode; arbitrary overrides are rejected. It is forbidden in `none` mode, which fails closed before update motion if it is nonempty;
- `HERMES_MAINTENANCE_BACKUP_MODE` — `default`, `force`, or `skip`;
- `HERMES_MAINTENANCE_RECEIPT_DIR` — receipt directory;
- `HERMES_MAINTENANCE_LOCK_PATH` — lock file;
- `HERMES_MAINTENANCE_TIMEOUT_SECONDS` — update timeout;
- `HERMES_MAINTENANCE_SYSTEMCTL_BIN` — systemctl path, primarily for proof fixtures.

`default` backup mode defers to Hermes Agent's own configured pre-update backup policy. The public tool does not silently suppress or force backup custody.

## No-gateway receipts

In `none` mode, the tool retains the normal version-before, update-check, optional update, and version-after sequence, but never invokes `systemctl` or `hermes gateway status`. A successful receipt includes `gateway_mode: "none"`, `gateway_restart_attempted: false`, `update_available`, and `updated`, with state `updated-no-gateway` or `current-no-gateway`.

## Boundaries

- The tool does not install Hermes Agent or a gateway service.
- The tool does not restart every Hermes profile.
- The tool does not invent a schedule.
- The tool does not retry a failed update by forcing or stashing source state.
- Gateway-owning modes require deterministic update and service receipts; a successful update command is not enough without gateway readback. `none` mode has no declared gateway boundary, so its completed version/update sequence and explicit no-gateway receipt are authoritative.
