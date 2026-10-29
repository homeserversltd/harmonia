# Yarr

This module maintains Yarr on an already-born appliance. It does not build Yarr, create users or directories, or own feed data.

The ladder:

- fails closed unless the birth-provided `/opt/yarr/yarr` executable exists;
- reads the appliance's ordered Yarr release sources, verifies the ZIP digest, and extracts only its `yarr` executable;
- leaves an identical executable alone; for a changed executable, atomically replaces it, restarts `yarr.service`, and checks the running process image;
- converges the quarry `yarr.service` unit with a backup of any replaced file;
- validates the installed unit;
- reloads systemd after file convergence;
- proves the service is active.

The unit runs `/opt/yarr/yarr` directly. Root `config.json` confirms Yarr's product port is `7070`; the unit relies on Yarr's matching default and requires no substituted value.

The public payload contains no credentials or filled secrets. `/var/lib/yarr/yarr.db` contains instance feed and application state and is not carried. `/home/yarr/.cache`, build output, temporary downloads, and logs are generated runtime or birth artifacts and are also excluded.

Birth supplies the initial Yarr executable, the `yarr` account and directories, and SQLite/package dependencies. The `yarr.home.arpa` virtual host belongs to the nginx concern. This module references those surfaces but does not absorb them.
