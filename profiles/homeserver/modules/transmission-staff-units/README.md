# Transmission staff units

This module carries fixed HOMESERVER systemd bytes for one native Transmission VPN singleton and its VPN port-forward readiness instance. Its single `files/converge` step treats `/etc` drift as a proposal and does not create an absent target. The module carries/proposes unit bytes only; it does not own placement or birth, install packages, enable units, create enablement links, reload systemd, start or stop services, or probe them.

`transmissionVPN.service` is the singleton daemon unit. It wants and orders after `network-online.target`, and it is ordered after `hold-port-forward@pia.service`, `transmissionPIA.service`, `transmission-daemon.service`, and `mnt-nas.mount`. Both `ConditionPathIsMountPoint=/vault` and `ConditionPathIsMountPoint=/mnt/nas` must pass before the singleton starts. The enabled singleton is wanted by `mnt-nas.mount`, so the NAS mount starts it. The owner enables it through portal service control; because the unit is wanted by `mnt-nas.mount`, that control creates `mnt-nas.mount.wants/transmissionVPN.service`, not `multi-user.target.wants/transmissionVPN.service`. This module does not create that link.

The singleton requires `hold-port-forward@pia.service`, and its `After=` dependency on the hold instance waits for that unit's `Type=notify` readiness before the daemon starts. The hold instance runs `transmission/vpn/namespace` as `ExecStartPre` and `transmission/vpn/hold` as its staff executable. Its `PartOf=transmissionVPN.service` relationship couples stop/restart operations to the singleton. The singleton runs `transmission/daemon` as `ExecStart` and `transmission/settings` as `ExecStartPost` through `/usr/local/sbin/agathodaimon/cli.py`.

Both units declare `Conflicts=` against `transmissionPIA.service` and `transmission-daemon.service`, and order after those services so their stops precede startup. The hold template declares no `[Install]` section.

This module does not replace or edit the legacy `transmission` module or its `transmissionPIA.service` and sysctl bytes. The units are fixed source bytes only: their presence here does not establish first placement/birth, enablement, or live service behavior.
