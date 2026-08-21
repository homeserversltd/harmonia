# Harmonia demo law

Harmonia does not use tests. All examples are live production demos.

The sole door is `harmonia demo <name>`. The demo registry is authoritative for names, listing, and dispatch. `harmonia demo` and `harmonia demo list` print the live registry; `harmonia demo <name>` runs exactly one registered production implementation.

A demo runs the real production implementation once. It may create bounded scratch state when needed. Its receipt must expose the observed result, cleanup observation, and any required readback. Scratch state is cleaned up and cleanup is observed before success is reported.

There are no compatibility aliases and no name-in-route forms. Use only the `demo` door and the registered demo name.
