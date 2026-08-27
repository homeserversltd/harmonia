# Calibre-Web

This module carries the HOMESERVER product Calibre-Web systemd desired state lifted from the private initialization quarry. Harmonia maintains configuration and service flags on an already-born appliance; it does not install Calibre-Web or Calibre, create the `calibre` account or directories, seed a library, or own application and library state.

The ladder:

- fails closed unless the birth-provided Calibre-Web Python environment, watcher script, `inotifywait`, and `calibredb` executables exist;
- converges the quarry `calibre-web.service` and `calibre-simple-watch.service` units with backups of replaced files;
- reloads systemd after file convergence;
- proves both services are active.

No filled secret exists in the quarry Calibre-Web configuration and none is carried. The quarry installer and `calibreSimpleWatcher.sh` are birth-owned software, not Harmonia configuration; their program text is not embedded in this manifest.

The units cross into birth-owned application and package paths under `/opt/calibre-web`, `/usr/local/sbin`, and the system executable search path. They also cross into instance-owned configuration, database, and log paths under `/etc/calibre-web`, `/var/lib/calibre-web`, and `/var/log/calibre-web`, and into NAS-owned library state under `/mnt/nas/books`. The nginx concern owns the `books.home.arpa` reverse proxy. This module does not absorb any of those concerns or their data.
