# Permissions

This HOMESERVER module is the Harmonia declaration point for sudoers policy owned by `https://github.com/homeserversltd/permissions.git`. The sidecar exposes that sovereign repository as the `sudoers` `source_artifact`; policy selection is driven by `profiles/homeserver/profile.json` in that repository.

The declaration has two consumers:

- Deployables lifts the sidecar through `harmonia_lift`, and Chrysalis packs the selected sovereign bytes into the birth body. A born target does not resolve a Fulcrum attachment or clone the repository.
- Harmonia uses the same profile declaration after birth to converge only the named files toward `/etc/sudoers.d`, with `root:root` ownership, mode `0440`, drift-only writes, and `visudo` validation before promotion.

The ladder is intentionally a scaffold: its `files/managed-files` step carries no embedded policy bytes. A later executable slice must resolve the selected profile paths from the packed/source-artifact boundary and populate typed managed-file declarations without creating a second policy tree here. Legacy flat `flask-*` files remain in place in the permissions repository.
