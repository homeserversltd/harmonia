#!/usr/bin/env bash
set -euo pipefail
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}

sink="$(pactl get-default-sink 2>/dev/null || true)"
if [ -z "${sink:-}" ]; then
  sink="$(pactl list short sinks 2>/dev/null | awk '/hdmi/{print $2; exit}')"
fi
[ -n "${sink:-}" ] || exit 0

case "${1:-}" in
  up)
    pactl set-sink-mute "$sink" 0
    pactl set-sink-volume "$sink" +5%
    ;;
  down)
    pactl set-sink-volume "$sink" -5%
    ;;
  mute)
    pactl set-sink-mute "$sink" toggle
    ;;
  *) exit 1 ;;
esac

info="$(pactl list sinks 2>/dev/null | awk -v sink="$sink" '
  $1=="Name:" && $2==sink {show=1}
  show && /Mute:/ {mute=$2}
  show && /Volume:/ && !vol {for (i=1;i<=NF;i++) if ($i ~ /%/) {gsub("/", "", $i); vol=$i; break}}
  show && /Formats:/ {exit}
  END {print mute, vol}
')"
set -- $info
mute="${1:-no}"
vol="${2:-0%}"
if [ "$mute" = "yes" ]; then
  text="Muted"
  value=0
else
  text="$vol"
  value="${vol%%%}"
fi

if command -v dunstify >/dev/null 2>&1; then
  dunstify     --app-name="volume"     --replace-id=91190     --stack-tag="volume"     --urgency=low     --expire-time=1200     --hint="int:value:${value}"     "Volume" "$text" >/dev/null 2>&1 || true
fi
