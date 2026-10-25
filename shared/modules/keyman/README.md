# Keyman runtime updates

HomeServer, HomeSI, HomeTV and the private HomeConsole link this one module.

The source synchronization remains for compatibility readers and Keyman member
census. The binary update uses the existing `release-binary/install` tool:
it resolves `sources.keyman` at the module's one declared `pinned_release_sha`,
binds the selected release to that exact source SHA, verifies the asset,
checksum sidecar and flag digest, and promotes
only differing bytes or metadata to `/vault/keyman/keyman`.

An unchanged binary is not replaced. A closed vault is skipped, and the
runtime parent must already exist from birth. No source installer is invoked.

Runtime support files and permissions, vault/key directory creation, temporary
exchange setup and credential seeding belong to birth or their named custody
tools. This module neither provisions nor changes keys, PINs or accounts, and
leaves existing compatibility runtime files untouched.
