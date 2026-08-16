# Transmission

This module carries the HOMESERVER product Transmission desired state lifted from the private initialization quarry. Harmonia maintains configuration and service flags on an already-born appliance; it does not install Transmission, create users or directories, acquire VPN credentials, or own download and runtime data.

The ladder:

- fails closed unless the birth-provided `transmission-daemon` and `/vault/scripts/transmission.py` launcher exist;
- requires the installed `settings.json` to be non-empty and valid JSON but never overwrites it;
- converges the quarry network buffer policy and Transmission VPN namespace unit with backups of replaced files;
- reloads systemd and restarts `transmissionPIA.service` only when this module changed managed material;
- enables the service when needed and proves it is active.

The public `settings.json` is a user-editable birth seed, not a maintenance overwrite. The quarry installer substitutions are applied exactly: `${PORT}` becomes the root `config.json` product port `9091`, `${ADMIN_USER}` becomes `admin`, and `${ADMIN_PASSWORD}` remains an unfilled birth-owned placeholder. The carried unit and sysctl policy otherwise preserve quarry text, apart from adding final newlines for repository-safe module form.

The unit is Transmission-owned namespace wiring even though the quarry stores it in the shared systemd file pack: it starts the external `/vault/scripts/transmission.py` launcher that creates the VPN path used by the nginx concern at `192.168.2.2:9091`. The launcher, VPN provider credentials, `/vault`, nginx virtual host and certificates remain owned by other concerns and are not absorbed here.

Mutable Transmission state under `/var/lib/transmission-daemon`, logs and runtime namespace/process state are instance artifacts and are not carried. Downloads under `/mnt/nas/downloads/{complete,incomplete,objectives}` cross into the NAS concern. The service account, group memberships, base-directory permissions, package, launcher dependencies and VPN credentials remain birth-owned.
