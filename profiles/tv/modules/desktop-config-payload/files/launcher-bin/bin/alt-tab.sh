#!/usr/bin/env bash
set -euo pipefail

# Global Hyprland Alt-Tab.
#
# Cycles through every normal mapped window, regardless of workspace.
# Ordering is deterministic "ladder" order:
#   workspace -> monitor -> top-to-bottom -> left-to-right -> address
# forward  = next item in that list, wrapping at the end
# backward = previous item in that list, wrapping at the beginning
#
# Usage: alt-tab.sh forward|backward

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 forward|backward" >&2
  exit 1
fi

command="$1"
case "$command" in
  forward|backward) ;;
  *)
    echo "Invalid argument: $command" >&2
    echo "Usage: $0 forward|backward" >&2
    exit 1
    ;;
esac

# address;monitor;workspace
# Exclude unmapped/hidden/internal/special-workspace windows.
mapfile -t windows < <(
  hyprctl clients -j | jq -r '
    [ .[]
      | select(.mapped != false)
      | select(.hidden != true)
      | select(.workspace.id != null and .workspace.id >= 0)
      | select((.class // "") != "")
    ]
    | sort_by(.workspace.id, .monitor, .at[1], .at[0], .address)
    | .[]
    | "\(.address);\(.monitor);\(.workspace.id)"
  '
)

count=${#windows[@]}
if [ "$count" -eq 0 ]; then
  exit 0
fi

active_address=$(hyprctl activewindow -j | jq -r '.address // empty')
active_index=-1
for i in "${!windows[@]}"; do
  IFS=';' read -r address _monitor _workspace <<< "${windows[$i]}"
  if [ "$address" = "$active_address" ]; then
    active_index=$i
    break
  fi
done

# If the active window is not in the list, start just before/after the list so
# the first command lands on the first/last eligible window.
if [ "$active_index" -ge 0 ]; then
  index=$active_index
elif [ "$command" = "forward" ]; then
  index=-1
else
  index=0
fi

case "$command" in
  forward)
    index=$(( (index + 1) % count ))
    ;;
  backward)
    index=$(( (index - 1 + count) % count ))
    ;;
esac

IFS=';' read -r address monitor workspace <<< "${windows[$index]}"

# Bring the target workspace/monitor into view, then focus the window by address.
hyprctl dispatch focusmonitor "$monitor" >/dev/null 2>&1 || true
hyprctl dispatch workspace "$workspace" >/dev/null 2>&1 || true
hyprctl dispatch focuswindow "address:$address" >/dev/null
