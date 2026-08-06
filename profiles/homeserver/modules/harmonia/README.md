# Harmonia self-maintenance

## Role

Harmonia keeps its own engine current through the same public source and receipt boundary used for other maintained concerns.

## Update path

The `harmonia-source-sync` ladder step obtains the declared Harmonia source at `/opt/harmonia/source` as bearer `owner`. The engine's native self-maintenance preflight compares the declared source head with the promoted state. It rebuilds and promotes `/usr/local/bin/harmonia` only when that source head moves, and emits truthful changed or converged-quiet receipts. Profile traversal records a failed module and continues to the remaining selected modules, so this concern is never a fail-fast escape from the profile receipt.

The program itself owns its installed schedule. The only lawful writer of `harmonia.service` and `harmonia.timer` is Harmonia's repository installer:

```text
/opt/harmonia/source/cli.py install --apply --with-systemd --enable-timer
```

The module does not carry a unit file, does not write a second update lane, and does not replace the installer. The installer refreshes the installed binary, profile capsule, and program-owned timer as one Harmonia-owned installation operation.

## Public boundary

This declaration reads only the credential selector supplied by the installed engine plane for its own source pull. It carries no token value, SSH key, credential write, private topology, or configuration hard-convergence surface.
