# Transmission staff units

This module carries only the fixed HOMESERVER systemd template bytes for the Transmission VPN hold and daemon units. Its single `files/converge` step treats `/etc` drift as a proposal and does not create an absent target. Placement/birth and the sibling staff interface are outside this module; it does not install packages, enable units, reload systemd, start or stop services, or probe them. Neither template declares `[Install]` enablement metadata, and this module creates no enablement or `.wants/` symlink. The hold unit retains its explicit `Wants=network-online.target` dependency.

The `hold-port-forward@%i.service` instance supplies `%i` as `{"provider":"%i"}` on standard input to `/usr/local/sbin/agathodaimon/cli.py transmission/vpn/hold`. The `transmission-vpn@%i.service` instance uses `%i` as the Web UI/RPC port read by sibling agathodaimon staff from `tabs.portals` in `/etc/appliance/config.json`; it is not the provider-forwarded peer port. The sibling agathodaimon staff starts these units on Caduceus order; this module neither selects provider credentials nor starts services.

Both units declare `Conflicts=` against `transmissionPIA.service` and `transmission-daemon.service`. Their `After=` lines include both conflicting services so systemd orders those services' stops before starting the corresponding new instance. The hold unit also orders itself after and wants `network-online.target`.

This module does not replace or edit the legacy `transmission` module, its `transmissionPIA.service`, or its sysctl file. The units are fixed source bytes only: their presence here does not establish birth placement, enablement, a working staff interface, or live service behavior.
