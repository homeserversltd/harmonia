# Harmonia control surface

Harmonia does not install or uninstall itself. Appliance installation and
removal are separate from its runtime control surface.

Harmonia retains the narrow systemd control surface for its own units:

```text
./cli.py
./cli.py build
./cli.py status
./cli.py install-timer
sudo ./cli.py install-timer --apply
sudo ./cli.py uninstall-timer --apply
```

The timer commands install, enable, disable, and remove only `harmonia.service`
and `harmonia.timer`. They do not install the binary, configuration, profiles,
state, logs, or receipts.

The appliance installer places and removes those installation
surfaces. Harmonia owns runtime convergence and its own systemd unit control;
these responsibilities are intentionally separate.
