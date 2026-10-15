# Household search

SearXNG provides local metasearch at `https://search.home.arpa`. It binds only to `127.0.0.1:8888`; the service is `searxng.service`. The Nginx site preserves the existing TLS and Tailscale-facing blocks and proxies to that explicit loopback address.

## Birth-owned payloads and credentials

The birth sidecar carries the current service unit, SearXNG settings, and the service-owned Nginx site. The settings preserve the castle's non-secret configuration and comments, except the inherited upstream API-key example comment, which is intentionally replaced with a generic, credential-free note. The live `server.secret_key` was removed before source transport and is represented only by `__SEARXNG_BIRTH_SECRET__`; birth must replace that marker with a per-appliance secret from `/root/key/skeleton.key`. No lab or castle secret is source material. The dormant GitHub Code engine keeps `ghc_auth.type: none` and its token is an empty string.

The read-only settings floor is module-local `settings-floor.py`, invoked with the born `/opt/searxng/searxng/bin/python`; it rides module source rather than `files_root` or a birth payload, and emits only `settings-valid` or `settings-invalid`.

The files are declared at birth as settings mode `0640` and unit/site mode `0644`. Birth owns initial secret generation and filling. This module does not create runtime directories, install packages, fetch or build SearXNG, or start or enable services.

## Harmonia boundary

The module's managed-files step declares those modes and presents `/etc` drift through the `interactable` whole-file proposal path. There is no field-level secret merge, and this source does not claim that a proposal exists or has been accepted. Maintenance does not automatically write a proposal or replace a birth-filled secret; the placeholder-bearing settings file must not be accepted as a replacement for a filled appliance file without preserving that unit's secret.

The floor is deliberately read-only apart from a truthful, same-run-change-gated systemd daemon reload: require the service unit to be loaded, the `/opt/searxng` runtime/source and virtual-environment interpreter to exist, and the settings to parse with the expected loopback bind, port, HTML/JSON formats, and a filled non-placeholder secret. It does not start, enable, restart, or claim that SearXNG is active or reachable. A parsed configuration and a loaded unit are not endpoint proof.

## Known work outside this module

- The sibling Portal contribution registry does not exist yet; this module creates no second registry and edits no Portal files. The current registry factory seed is `profiles/homeserver/modules/coronatio/files_root/etc/appliance/config.factory:41-65`; runtime `/etc/appliance/config.json` is read in Caduceus at `src/lib/config.rs:119-124` and `routes/appliance/service/support/control_service/index.rs:114-134`. The owning Portal lane still needs to add the customer record `Search`, service `searxng.service` (and `nginx.service` only if its route model requires it), and URL `https://search.home.arpa`.
- The existing search DNS record remains unchanged. Its `192.168.123.1` target in the firewall Unbound source (line 29) shares the hardcoded address used for Matrix/Chat in Element's `matrix.conf` lines 2-4. DNS changes are outside this slice.
- Legacy SearX files remain untouched.
