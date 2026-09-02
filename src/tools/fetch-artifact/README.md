# fetch-artifact

Fetches a verified artifact from the configured registry or, when `release_repo` is present, the component's Forgejo Release. Native releases derive the tag and x86_64 asset names from `source_dir/Cargo.toml`, fetch the checksum sidecar, and atomically stage only after strict verification. Native release acquisition never falls back to a registry or source build.
