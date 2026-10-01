# fetch-artifact

Fetches a verified artifact from the configured registry or, when `release_repo` is present, the component's Forgejo Releases. Native release selection uses the newest published Release, ordered by `created_at` and then release `id`, that has the requested component asset, checksum sidecar, and `release.flag`. A HEAD without its own Release therefore uses the newest eligible Release that exists.

In artifact mode, failure to retrieve an eligible Release is a named refusal: preserve the installed binary and do not fall back to a registry or source build. Developer mode bypasses native Release acquisition and builds `main`; it must not install a Release instead.
