# HomeConsole console session

This module owns the Steam Gaming Mode Wayland session entry and retires only `/usr/local/bin/steam-gamescope-session`. It owns no SDDM file.

The session entry is exactly:

```ini
[Desktop Entry]
Name=Steam Gaming Mode
Comment=Steam Big Picture/Gamepad UI through Gamescope
Exec=/usr/local/sbin/agathodaimon/cli.py console session
Type=Application
DesktopNames=gamescope-steam
```

The ladder converges the entry above and removes only `/usr/local/bin/steam-gamescope-session`.
