# firewall

Visible HOMESERVER public scaffold for the `firewall` Chrysalis concern phase.

Firewall/network policy concern: nftables, DNS/Unbound, DHCP/Kea, networkd/sysctl, and firmware/network posture when applicable.

This folder is desired-state/config authority only. It installs nothing by itself, carries no secrets, and is consumed later by a single Chrysalis phase/unit for `firewall`.
