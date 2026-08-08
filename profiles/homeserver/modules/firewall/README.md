# Firewall

This module carries the HOMESERVER product network spine lifted from the private initialization quarry. Harmonia maintains configuration on an already-born appliance; it does not install nftables, Unbound, Kea, systemd-networkd, firmware, or packages.

The ladder:

- fails closed unless the birth-provided network executables and validators exist;
- requires the four user-editable host/site files to exist but never overwrites them;
- converges six product-owned policy files with backups of replaced files;
- validates nftables, Unbound, Kea, and the nftables unit;
- reloads systemd and restarts nftables, Unbound, and Kea only when this module changed managed material;
- proves those services and systemd-networkd are active.

## User-editable boundary

The quarry bytes for `10-wan0.network`, `20-lan0.network`, and `kea-dhcp4.conf` are carried for birth/export parity, but the maintenance ladder only asserts the installed copies are non-empty. It does not overwrite them. They bind physical interface names, static addressing, and DHCP reservations; replacing a locally adapted copy can sever remote access. The public Kea seed preserves the quarry subnet, pool, and options but deliberately removes the two instance MAC reservations (`reservations: []`). This classification and adaptation are proposals for operator verdict, not settled product law.

## Generated and external surfaces

The module does not carry generated MAC `.link` files, `/etc/unbound/blocklist.conf`, Kea leases, logs, caches, certificates, credentials, or filled secrets. It also excludes the quarry `resolv.conf` because its Tailscale search domain is instance-owned, and excludes `laptop-home-arpa.conf` because its laptop addresses are instance DNS. Quarry Python installers, adblock generators, scripts, and tests do not cross into the manifest; manifests contain declarations, never executable program text.

The desired configuration crosses into other owners without absorbing them: birth supplies packages, users, service units, interface discovery, and the initial user-editable files; the adblock generator owns `blocklist.conf`; system CA custody owns `/etc/ssl/certs/ca-certificates.crt`; Kea owns `/var/lib/kea`; Tailscale owns `tailscale0`; systemd owns networkd and wait-online executables. Networkd and sysctl changes are deliberately not activated by an unconditional service restart; their live activation remains a separately authorized appliance transition.
