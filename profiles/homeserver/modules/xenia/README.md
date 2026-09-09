# Xenia

This fixed homeserver module reads the public `appliance.xenia.v1` guest register and lowers enabled process guests into isolated service routines. It does not create accounts, directories, or register bytes. The retire declaration only manages unit files bearing the matching `X-Xenia-Id` marker.

The manifest contains only the declaration-only `xenia/converge` and `xenia/retire` steps. Runtime details are derived from each validated register entry.
