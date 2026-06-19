# TV payload authority

Harmonia owns the canonical maintenance payload/config authority for the Arch TV appliance surfaces that are not Make Modern substrate.

Proclamation:

```text
If a TV surface is part of Make Modern substrate itself, Make Modern owns its convergence.
Every other deployable-managed TV config/runtime surface is tied to Harmonia.
Deployables consume the Harmonia-owned payload during birth by safe repository symlink or declared export/vendor step with a receipt.
The land does not carry two hand-maintained TV payload trees.
```

The authority manifest is `payloads/tv/index.json`.

Current deployable consumption target:

```text
repo: forgejo:HOMESERVERSLTD/deployables
path: arch/rolling/arch-tv
```

Owned TV surfaces include owner profile, GPU/display stack, Hyprland desktop, operator rc profile, desktop config payload, user session services, SDDM autologin, optional Steam/Gamescope lane, power/controller maintenance, console recovery, and appliance proof.

Desktop payload examples under this authority include Hyprland, Waybar, Dunst, Kitty, Wofi, Chromium policy/MIME/KDE surfaces, user systemd services, shell rc files, and helper scripts.
