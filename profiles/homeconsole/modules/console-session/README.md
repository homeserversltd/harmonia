# HomeConsole console session

This module owns the Steam Gaming Mode Wayland session entry and restores SDDM's `Xsetup` from the Ubuntu package rather than authoring a replacement script.

The session entry is exactly:

```ini
[Desktop Entry]
Name=Steam Gaming Mode
Comment=Steam Big Picture/Gamepad UI through Gamescope
Exec=/usr/local/sbin/agathodaimon/cli.py console session
Type=Application
DesktopNames=gamescope-steam
```

`files_root/usr/share/sddm/scripts/Xsetup` is byte-for-byte `usr/share/sddm/scripts/Xsetup` from Ubuntu package `sddm_0.21.0+git20251101.dfa5315-1ubuntu2_amd64.deb`, downloaded from <https://archive.ubuntu.com/ubuntu/pool/universe/s/sddm/sddm_0.21.0+git20251101.dfa5315-1ubuntu2_amd64.deb>. Package SHA-256: `79c9c4dff1bf6628d5826c114b094cdca1d0df8f5adc71020f9f860c77d482a8`. Extracted file: 2592 bytes, mode `0755`, SHA-256 `8dfb44283dfe1afb84051bd51acb6bec92da5c7b3a855462c503d4f07ba3ce78`. The vendor bytes do not impose a forced 1920x1080 display pin and preserve the package's Prime/display arrangement.

The ladder converges the desktop entry and packaged `Xsetup` separately with explicit modes and root ownership, then removes only `/usr/local/bin/steam-gamescope-session`. It leaves `/etc/sddm.conf.d/20-homeconsole-display.conf` and the separate HomeConsole autologin declaration untouched.
