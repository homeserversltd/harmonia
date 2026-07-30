# Samba

This module carries the HOMESERVER product Samba and LAN discovery desired state lifted from the private initialization quarry. Harmonia maintains configuration and service flags on an already-born appliance; it does not install Samba, Avahi, or WSDD, create Samba users, set passwords, or own NAS mounts and data.

The ladder:

- fails closed unless the birth-provided `smbd`, `nmbd`, `testparm`, `avahi-daemon`, and `wsdd2` executables exist;
- requires the installed `/etc/samba/smb.conf` and `/etc/hosts` to be non-empty but never overwrites them;
- validates the installed Samba configuration with `testparm`;
- converges the quarry Avahi host map and Samba discovery service with backups of replaced files;
- restarts Avahi only when this module changed those managed Avahi files;
- enables the four declared services when needed and proves each is active.

The public `smb.conf` and `hosts` copies are user-editable birth seeds, not maintenance overwrites. The Samba seed resolves the quarry `${ADMIN_USER}` placeholder to root `config.json`'s product administrator `owner`. The literal `192.168.123.1`, `home`, `home.local`, and `home.arpa` values are the quarry product values. All four carried files otherwise preserve quarry text; the public copies only remove trailing spaces and add final newlines for repository-safe module form. This is the conservative candidate policy pending operator verdict on the per-file table in publication.

The quarry `install.py` is birth logic, not desired configuration. Its package installation remains a deployable birth debt. Its `/etc/nsswitch.conf` rewrite crosses into system name resolution, `/mnt/nas` ownership crosses into the storage/mount concern, and its service activation crosses into systemd. The module carries only the Samba tree's own four configuration files and does not absorb configuration from those concerns.

The installer reads `/root/key/skeleton.key` and writes Samba's private password database for `owner` and `root`. Those filled secrets and generated instance records are excluded. Samba databases, locks, PID files, caches, logs, NAS contents, and Avahi/WSDD runtime state are also excluded.
