# Yarr

This module carries the HOMESERVER product Yarr desired state lifted from the private initialization quarry. Harmonia maintains configuration on an already-born appliance; it does not install packages or Go, clone or build Yarr, create users or directories, or own feed data.

The ladder:

- fails closed unless the birth-provided Go runtime and Yarr source tree exist;
- converges the quarry `yarr.service` unit with a backup of any replaced file;
- validates the installed unit;
- reloads systemd after file convergence;
- proves the service is active.

The unit is carried byte-for-byte. Root `config.json` confirms Yarr's product port is `7070`; the unit relies on Yarr's matching default and requires no substituted value.

The public payload contains no credentials or filled secrets. `/var/lib/yarr/yarr.db` contains instance feed and application state and is not carried. `/home/yarr/.cache`, build output, temporary downloads, and logs are generated runtime or birth artifacts and are also excluded.

Yarr's source tree under `/opt/yarr`, the Go runtime under `/usr/local/go`, the `yarr` account and directories, and SQLite/package dependencies belong to birth. The `yarr.home.arpa` virtual host belongs to the nginx concern. This module references those surfaces but does not absorb them.
