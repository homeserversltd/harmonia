# PostgreSQL

This module carries the HOMESERVER product PostgreSQL desired configuration. Harmonia maintains configuration and service flags on an already-born appliance; it does not install PostgreSQL, initialize or erase a cluster, create database roles or tablespaces, fill passwords, or own database data.

The ladder:

- fails closed unless the birth-provided PostgreSQL executable exists at the product path;
- converges the product configuration and unit with backups of replaced files;
- masks the Debian instance template so only the HOMESERVER unit owns the cluster;
- asks PostgreSQL to parse the installed main configuration;
- reloads systemd and restarts PostgreSQL only when this module changed managed material;
- enables the HOMESERVER unit and proves it is active.

The payload preserves the product configuration bytes. The versioned package directories are reached through the birth-owned `/opt/homeserver/postgresql/current` and `/opt/homeserver/postgresql/bin` links. The module does not create those links or the `postgres` account.

The configuration crosses into the birth-owned cluster and RAM tablespace under `/mnt/ramdisk/postgresql`. Cluster files, role passwords, sockets and PID files, logs, NAS backups, and generated certificates are runtime or instance state and are not carried. Service units for Forgejo, Vaultwarden, Matrix, Mealie, and other database clients may depend on `postgresql.service`; those services and their configuration remain outside this module.

The lifted `tuning.conf` and `ramdisk.conf` are preserved under `conf.d` exactly as supplied. The lifted `postgresql.conf` does not include `conf.d`, so this module does not invent an include directive or claim those two files are active.
