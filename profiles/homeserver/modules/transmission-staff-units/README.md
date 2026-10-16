# Transmission staff units

This module carries fixed HOMESERVER systemd bytes for the native Transmission VPN singleton and its VPN port-forward readiness instance. Its single `files/converge` step treats `/etc` drift as a proposal and does not create an absent target. The module carries/proposes unit bytes only; it does not own placement or birth, install packages, enable units, create enablement links, reload systemd, start or stop services, or probe them.

## Boot and mount ordering

`transmissionVPN.service` is wanted by both `vault.mount` and `mnt-nas.mount`, so a systemd start of either mount requests the enabled service. A mount made outside systemd (for example a direct `mount` of `/vault`) runs no start job and pulls in nothing; that path relies on the service being started by its other trigger. Both units also declare `RequiresMountsFor=/vault /mnt/nas` and exact `ConditionPathIsMountPoint=` guards for both paths. The hold carries `RequiresMountsFor=` as well as explicit mount ordering so an independent hold start pulls in and waits for the same mounts. The mount requirements pull in and order the required mounts; the conditions prevent either service from starting unless both paths are actual mount points. `network-online.target` is wanted and ordered before both units. These declarations describe the retry path, not proof that either mount or service is active on a body.

The owner enables the singleton through portal service control; the resulting links are owned by that control and this module does not create them. No source step enables either unit, reloads systemd, or starts/stops services.

## Readiness and lifecycle

The singleton has `Requires=hold-port-forward@pia.service` and orders after it. The hold template is `Type=notify`, so the singleton cannot proceed until the hold reports readiness; an unsuccessful required hold prevents the singleton from starting. The hold runs `transmission/vpn/namespace` as `ExecStartPre` and `transmission/vpn/hold` as its staff executable. It no longer uses `PartOf=`. Instead, `Upholds=transmissionVPN.service` lets an active hold request the singleton again if it becomes inactive or failed, including after a dependency failure, subject to the singleton's own conditions and dependencies.

The singleton is also `Type=notify` with `NotifyAccess=all` and `TimeoutStartSec=180`. Its `ExecStartPost` settings command therefore runs only after the daemon reports `READY=1`; the existing daemon and settings commands, stdin payload, environment, and restart delays are preserved. Whether the running Transmission daemon actually supplies the expected readiness notification still needs a live witness; this source change does not establish that behavior.

`PropagatesStopTo=hold-port-forward@pia.service` makes an explicit stop of the singleton stop its hold too. A restart of the singleton, or its own `Restart=on-failure`, does not propagate a stop: the hold, its tunnel and its forwarded port stay up across a daemon-only restart (witnessed on the castle 2026-10-16, forward port 41319 unchanged). The hold's `Restart=on-failure` remains active with its 30-second delay, and the singleton's remains active with its 10-second delay. `StartLimitIntervalSec=0` on both units disables start-rate throttling, so retries are not permanently suppressed after repeated failures; each restart still has its configured delay and start timeout.

Both units declare `Conflicts=` against `transmissionPIA.service` and `transmission-daemon.service`, and order after those services so their stops precede startup. The hold template declares no `[Install]` section. The units retain the `/vault` and `/mnt/nas` guards for independent starts as well as starts pulled through the singleton.

This module does not replace or edit the legacy `transmission` module or its `transmissionPIA.service` and sysctl bytes. The units are fixed source bytes only: their presence here does not establish first placement/birth, enablement, daemon readiness, or live service behavior. A live witness remains pending.
