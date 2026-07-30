# Tailscale

This module carries the HOMESERVER product Tailscale daemon defaults lifted byte-for-byte from the private initialization quarry. Harmonia maintains configuration and service flags on an already-born appliance; it does not add package repositories, install Tailscale, create daemon state directories, authenticate a node, or join a tailnet.

The ladder:

- fails closed unless the birth-provided `tailscaled` executable exists;
- converges `/etc/default/tailscaled` with a backup of any replaced file;
- preserves the quarry ownership (`owner:owner`) and file mode (`0644` through the files convergence primitive);
- restarts `tailscaled.service` only when this module changed the managed defaults;
- enables the service and proves it is active.

The quarry has no dedicated validator for `/etc/default/tailscaled`, so the ladder does not invent one. Harmonia's `validate-ladder` checks the module schema and tool/permutation contract; it does not prove that a live daemon accepts these defaults.

The config references `/var/lib/tailscale`, which holds node identity and persistent daemon state, and `/run/tailscale`, which is runtime state created outside this module. Neither directory nor its contents are carried. Auth keys, node identity, tailnet policy, route approval, and daemon preferences written by `tailscale up` remain birth/operator-owned.

The quarry continuity note declares `192.168.123.0/24` subnet advertisement as desired operating posture but explicitly keeps it out of installer-managed configuration. This lift therefore does not turn that preference into a manifest command. The root `config.json` lists Tailscale-facing ports for Jellyfin, Transmission, Piwigo, MkDocs, Vaultwarden, Forgejo, Navidrome, FileBrowser, Calibre-Web, and Yarr; those service/proxy crossings are not consumed by the daemon defaults and remain owned by their respective concerns.
