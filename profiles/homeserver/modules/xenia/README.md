# Xenia

This fixed homeserver module reads the public `appliance.xenia.v1` guest register and lowers enabled process guests into isolated service routines. It does not create accounts, directories, or register bytes. The retire declaration only manages unit files bearing the matching `X-Xenia-Id` marker.

## Clone road

An entry with `source.kind=clone` uses `source.repo` and `source.ref`. Each apply fetches and checks out the resolved Git revision in the configurable `HARMONIA_XENIA_ROOT` seat (default `/var/lib/xenia/<id>`), retaining the checkout's `.git` directory and untracked `target/` build cache. Non-fast-forward movement is refused as `xenia-clone-diverged`; the seat is repaired to the declared owner and mode `0750` after checkout. Absent `source.kind` or `source.kind=release` keeps the existing `source.release_repo` and `source.ref` release road.

## Clone face ladder

For a clone with `install.bin`, the face ladder first requests the exact checked-out SHA release asset and `.sha256` sidecar. A miss falls back to `cargo build --release --locked` from the checkout with `CARTRIDGE_SOURCE_SHA` set, and installs the embedded-SHA binary. A failed face only degrades that Xenia entry; sibling entries continue. The running guest is health-read before restart, restarted when its binary/files or running source SHA differ, and health-read again afterward before the observed SHA is stamped. Entries without an install face are staff-only: they perform the clone checkout and skip binary, unit, restart, and status work.
