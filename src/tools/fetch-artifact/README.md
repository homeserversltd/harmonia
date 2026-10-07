# fetch-artifact

Fetches a verified artifact from the configured registry or, when `release_repo` is present, the component's Forgejo Releases. Native release selection uses the newest published Release, ordered by `created_at` and then release `id`, that has the requested component asset, checksum sidecar, and `release.flag`. A HEAD without its own Release therefore uses the newest eligible Release that exists.

Caduceus Releases always carry and verify the four profile asset/sidecar pairs (`homeserver`, `homeconsole`, `tv`, and `probe`), regardless of the installed profile. The declared asset name selects only the binary to install; verification downloads all four pairs, and selecting any one asset does not require a matching profile. `release.flag.sha256` is checked against the aggregate digest of all four pairs.

In artifact mode, failure to retrieve an eligible Release is a named refusal: preserve the installed binary and do not fall back to a registry or source build. Developer mode bypasses native Release acquisition and builds `main`; it must not install a Release instead.
