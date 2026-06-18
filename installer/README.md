# Harmonia installer

Harmonia is self-contained: this repository carries the commands that build, install, inspect, and uninstall the runnable binary it ships.

Root doorway:

```text
./cli.py
./cli.py build
./cli.py install
sudo ./cli.py install --apply
./cli.py status
sudo ./cli.py uninstall --apply
```

The installer tranche installs:

- `/usr/local/bin/harmonia`
- `/etc/harmonia/profiles/`
- `/etc/harmonia/modules/`
- `/etc/harmonia/locks/`
- `/var/lib/harmonia/state/`
- `/var/log/harmonia/`
- `/var/lib/harmonia/receipts/`
- optional `harmonia.service`
- optional `harmonia.timer`

Default `install` and `uninstall` are dry-run plans. Add `--apply` to mutate the machine.

Python is the installer doorway only. Harmonia's update logic remains in the Rust binary and profile/tool graph.
