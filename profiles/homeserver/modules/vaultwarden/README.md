# Vaultwarden

This module carries the HOMESERVER product Vaultwarden desired state lifted from the private initialization quarry. Harmonia maintains configuration and service flags on an already-born appliance; it does not install or build Vaultwarden, install Rust or other dependencies, create accounts or directories, initialize PostgreSQL, download the web vault, or own vault data.

The ladder:

- fails closed unless the birth-provided Vaultwarden executable exists;
- requires the installed secret-bearing `/etc/vaultwarden.env` to be non-empty but never overwrites it;
- converges the quarry `vaultwarden.service` unit with a backup of any replaced file;
- validates the installed unit with `systemd-analyze verify`;
- reloads systemd and restarts Vaultwarden only when this module changed managed material;
- enables the service when needed and proves it is active.

The public environment file is a user-editable birth template, not a maintenance overwrite. Its quarry `${ROCKET_PORT}` placeholder is resolved to the product port `8200`; `${ADMIN_TOKEN}` and `${DB_PASSWORD}` remain unfilled birth-owned placeholders. The installer hashes and fills the administrator token and database password during birth. Both carried files otherwise preserve quarry text; the public copies only remove trailing spaces and add final newlines for repository-safe module form.

Vault database, attachments, icon cache, and log files under `/var/lib/vaultwarden` and `/var/log/vaultwarden` are instance material and are not carried. The unit crosses into the birth-owned binary and web vault under `/opt/vaultwarden`, the PostgreSQL concern through `postgresql.service` and the database URL, and the network concern through `network.target`. The nginx concern owns the `vault.home.arpa` reverse proxy. The quarry installer also names `/mnt/nas/vaultwarden`, but its `NAS_PATH` replacement has no matching environment-template placeholder and does not feed either carried file. This module does not absorb any of those concerns.
