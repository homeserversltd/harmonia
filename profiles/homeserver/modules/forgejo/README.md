# Forgejo

This module carries the HOMESERVER product Forgejo desired state lifted from the private initialization quarry. Harmonia maintains configuration and service flags on an already-born appliance; it does not download Forgejo, create users or directories, initialize PostgreSQL, create an administrator, manage SSH credentials, or own repository data.

The ladder:

- fails closed unless the birth-provided `/opt/forgejo/forgejo` executable exists;
- requires the installed birth-owned `/opt/forgejo/custom/conf/app.ini` to be non-empty but never overwrites it;
- converges the quarry `forgejo.service` unit with a backup of any replaced file;
- reloads systemd after file convergence;
- proves the service is active and probes its loopback HTTP endpoint.

The public `app.ini` is a user-editable birth seed, not a maintenance overwrite. `${PG_PASS}` and `${SECRET_KEY}` remain unfilled birth-owned placeholders; first birth replaces them and Forgejo may add instance-generated secret keys. The carried template and unit otherwise preserve quarry bytes, with only a final newline retained for repository-safe module form. The alternate `manual_deploy.py` adds a `[webhook]` private-host allowance that the primary quarry installer does not add; this lift does not silently choose that divergent manual-deploy adaptation.

Forgejo repositories under `/opt/forgejo/repositories`, application data under `/opt/forgejo/data`, logs under `/var/log/forgejo`, generated session files, and runtime state are instance artifacts and are not carried. The unit crosses into the PostgreSQL concern through `postgresql.service` and the configured database, and into the network concern through `network.target`. The nginx concern owns the `git.home.arpa` reverse proxy and certificates. Birth owns the `git` user and group, directory creation and permissions, database role/schema/extension, administrator creation, SSH `AuthorizedKeysCommand` policy, and any authorized-keys file. Migration and administration scripts remain quarry tools and are not absorbed.
