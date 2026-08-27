# Jellyfin

This module carries the HOMESERVER product Jellyfin desired state lifted from the private initialization quarry. Harmonia maintains configuration on an already-born appliance; it does not install Jellyfin, add package repositories, create users or directories, or own media and runtime data.

The ladder:

- fails closed unless the birth-provided `jellyfin` executable exists;
- converges the quarry `jellyfin.service` unit with a backup of any replaced file;
- preserves `system.xml` as a user-editable birth seed and never overwrites the appliance copy;
- reloads systemd after file convergence;
- proves the service is active.

The public payload contains no credentials or filled secrets. The quarry `${PORT}` installer placeholder in the user-editable `system.xml` seed is resolved to the product port `8096` from root `config.json`.

Jellyfin owns mutable state under `/var/lib/jellyfin`, `/var/cache/jellyfin`, and `/var/log/jellyfin`; those instance artifacts are not carried. Media under `/mnt/nas/media` crosses into the NAS concern, and web assets under `/usr/share/jellyfin/web` cross into the birth-provided Jellyfin package. This module does not absorb either surface.
