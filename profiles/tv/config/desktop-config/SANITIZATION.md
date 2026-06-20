# Arch TV payload sanitization

The source desktop payload came from `/var/opt/hermes/workspace/deployable-tv-desktop-config-20260615-164414`.

TV baseline changes applied before module packaging:

- removed Waybar `custom/clipboard`, `custom/printer`, `backlight`, and `battery` from active module lists;
- removed `openwhispr` autostart;
- removed laptop instant-DPMS `swayidle timeout 0` autostart;
- restored provided `alt-tab.sh` global window cycler and Alt-Tab/Alt-Shift-Tab bindings;
- replaced old `/home/anon` references with non-broken `/home/owner` or `git push` equivalents;
- left Gamescope only in the optional Steam game lane, not in SDDM autologin.
