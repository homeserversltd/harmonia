# Transmission staff units

This module carries fixed HOMESERVER systemd bytes for one native Transmission VPN singleton and its VPN port-forward readiness instance. Its single `files/converge` step treats `/etc` drift as a proposal and does not create an absent target. Placement/birth and live behavior are outside this module; it does not install packages, enable units, reload systemd, start or stop services, or probe them.

`transmissionVPN.service` is the singleton daemon unit. It requires `hold-port-forward@pia.service`, and its `After=` dependency on the hold instance waits for that unit's `Type=notify` readiness before the daemon starts. The hold instance runs `transmission/vpn/namespace` as `ExecStartPre` and `transmission/vpn/hold` as its staff executable. Its `PartOf=transmissionVPN.service` relationship couples stop/restart operations to the singleton. The singleton runs `transmission/daemon` as `ExecStart` and `transmission/settings` as `ExecStartPost` through `/usr/local/sbin/agathodaimon/cli.py`.

The singleton's `[Install]` `WantedBy=multi-user.target` is metadata only; this module does not enable it or create an enablement or `.wants/` symlink. The hold template declares no `[Install]` section. Both units declare `Conflicts=` against `transmissionPIA.service` and `transmission-daemon.service`, and order after those services so their stops precede startup.

This module does not replace or edit the legacy `transmission` module or its `transmissionPIA.service` and sysctl bytes. The units are fixed source bytes only: their presence here does not establish first placement/birth, enablement, or live service behavior.
