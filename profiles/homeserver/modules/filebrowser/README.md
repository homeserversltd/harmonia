# File Browser

This module carries the HOMESERVER product File Browser service configuration lifted from the private initialization quarry. Harmonia maintains configuration on an already-born appliance; it does not install File Browser, create users or directories, initialize its database, or create credentials.

The ladder:

- fails closed unless the birth-provided `/usr/local/bin/filebrowser` executable exists;
- converges the quarry-derived `filebrowser.service` unit with a backup of any replaced file;
- leaves `/etc/filebrowser/filebrowser.db` untouched as mutable instance state;
- reloads systemd and restarts File Browser only when this module changed managed material;
- enables the service when needed and proves it is active.

The quarry installer writes product settings and the factory-admin credential into the same mutable database. Root `config.json` supplies port `8081`, but neither the database nor its filled credential is public desired-state payload.

The unit crosses into the NAS mount at `/mnt/nas`, the birth-provided binary at `/usr/local/bin/filebrowser`, and instance state at `/etc/filebrowser/filebrowser.db`. The quarry installer also reads `/root/key/skeleton.key`; the nginx concern owns the File Browser reverse-proxy site. This module does not absorb any of those surfaces.
