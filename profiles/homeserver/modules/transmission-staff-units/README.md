# Transmission staff units

This module carries fixed HOMESERVER systemd bytes for the native Transmission VPN singleton and its VPN port-forward readiness instance. Its `files/converge` step treats recognized `/etc` drift as a proposal and does not create an absent target. The following `systemd daemon-reload` step is gated on the module's unit bytes changing: it reloads after an accepted write, not when a proposal is merely shown or on an unchanged pass. The module does not own first placement or birth, install packages, enable units, or start, stop, or restart services.

## Boot and mount ordering

`transmissionVPN.service` is wanted by both `vault.mount` and `mnt-nas.mount`, so a systemd start of either mount requests the enabled service. A mount made outside systemd (for example a direct `mount` of `/vault`) runs no start job and pulls in nothing; that path relies on the service being started by its other trigger. Both units order after `vault.mount` and `mnt-nas.mount` and check that `/vault` and `/mnt/nas` are mount points. These directives order and guard service starts but do not pull in either mount. `network-online.target` is wanted and ordered before both units.

The owner enables the singleton through portal service control; the resulting links are owned by that control and this module does not create them.

## Readiness and lifecycle

The singleton requires, binds to, and orders after `hold-port-forward@pia.service`. The hold template is `Type=notify`, so the singleton cannot proceed until the hold reports readiness. The hold runs `transmission/vpn/namespace` as `ExecStartPre` and `transmission/vpn/hold` as its staff executable. If the hold goes inactive or fails, `BindsTo=` stops the singleton. The hold has `Restart=no` and no `Upholds=`: it neither restarts itself nor requests another start of the singleton.

The singleton is also `Type=notify` with `NotifyAccess=all` and `TimeoutStartSec=180`. Its `ExecStartPost` settings command therefore runs only after the daemon reports `READY=1`; the existing daemon and settings commands, stdin payload, and environment are preserved. Whether the running Transmission daemon actually supplies the expected readiness notification still needs a live witness; this source change does not establish that behavior.

`PropagatesStopTo=hold-port-forward@pia.service` makes an explicit stop of the singleton stop its hold too. A daemon-only restart leaves the hold, its tunnel, and its forwarded port up. The singleton retains `Restart=on-failure` with a 10-second delay for a daemon failure; a dependency stop when the hold trips does not trigger that restart. `StartLimitIntervalSec=0` remains unchanged on both units.

Both units declare `Conflicts=` against `transmissionPIA.service` and `transmission-daemon.service`, and order after those services so their stops precede startup. The hold template declares no `[Install]` section. The units retain the `/vault` and `/mnt/nas` guards for independent starts as well as starts pulled through the singleton.

This module does not replace or edit the legacy `transmission` module or its `transmissionPIA.service` and sysctl bytes. The units are fixed source bytes only: their presence here does not establish first placement/birth, enablement, daemon readiness, or live service behavior. A live witness remains pending.
