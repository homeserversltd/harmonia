#!/usr/bin/env bash
set -u

socket_path="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/hypr/${HYPRLAND_INSTANCE_SIGNATURE}/.socket2.sock"

float_bitwarden_windows() {
  tmp=$(mktemp)
  hyprctl clients -j > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
  python3 - "$tmp" <<'PY' | while IFS= read -r addr; do
import json, sys
from pathlib import Path
try:
    rows = json.loads(Path(sys.argv[1]).read_text())
except Exception:
    rows = []
extension_id = "nngceckbapebfimnlniiiahkandclblb"
for c in rows:
    fields = " ".join(str(c.get(k, "")) for k in ("class", "title", "initialClass", "initialTitle", "xdgTag", "xdgDescription")).lower()
    if ("bitwarden" in fields or extension_id in fields) and not c.get("floating"):
        addr = str(c.get("address", "")).strip()
        if addr:
            print(addr)
PY
    [ -n "$addr" ] || continue
    hyprctl dispatch setfloating "address:$addr" >/dev/null 2>&1 || true
    hyprctl dispatch centerwindow "address:$addr" >/dev/null 2>&1 || true
  done
  rm -f "$tmp"
}

float_bitwarden_windows

[ -S "$socket_path" ] || exit 0
socat -U - "UNIX-CONNECT:$socket_path" | while IFS= read -r line; do
  case "$line" in
    openwindow*|windowtitle*|activewindow*|activewindowv2*)
      sleep 0.08
      float_bitwarden_windows
      ;;
  esac
done
