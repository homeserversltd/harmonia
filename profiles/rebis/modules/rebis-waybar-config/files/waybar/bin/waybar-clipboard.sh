#!/usr/bin/env bash
set -euo pipefail

# Waybar clipboard helper for Hyprland/Wayland.
# status: prints Waybar JSON with clipboard preview
# paste:  safely paste current clipboard into the active app/terminal using ydotool
# raw-paste: paste without temporary newline/control-character cleanup
# pick: open clipman history picker; selected item becomes current clipboard

max_preview=36

notify() {
  if command -v notify-send >/dev/null 2>&1; then
    notify-send -a "Clipboard Button" "$1" "${2:-}"
  fi
}

get_clip() {
  wl-paste --no-newline 2>/dev/null || true
}

json_status() {
  local clip preview tooltip class
  clip="$(get_clip)"
  if [[ -z "$clip" ]]; then
    jq -cn --arg text "" --arg tooltip "Clipboard is empty\nLeft click: paste\nRight click: clipboard history" \
      '{text:$text, tooltip:$tooltip, class:"empty"}'
    return
  fi

  preview="$(printf '%s' "$clip" | tr '\r\n\t' '   ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
  if ((${#preview} > max_preview)); then
    preview="${preview:0:max_preview}…"
  fi
  tooltip="$(printf '%s' "$clip" | head -c 1800 | python3 -c 'import html,sys; print(html.escape(sys.stdin.read()), end="")')"
  class="ready"
  if [[ "$clip" == *$'\n'* ]]; then
    class="multiline"
  fi

  jq -cn --arg text " ${preview}" --arg tooltip "$tooltip" --arg class "$class" \
    '{text:$text, tooltip:$tooltip, class:$class}'
}

active_is_terminal() {
  local info class title
  info="$(hyprctl activewindow -j 2>/dev/null || true)"
  class="$(jq -r '.class // ""' <<<"$info" 2>/dev/null | tr '[:upper:]' '[:lower:]')"
  title="$(jq -r '.title // ""' <<<"$info" 2>/dev/null | tr '[:upper:]' '[:lower:]')"
  [[ "$class $title" =~ (kitty|alacritty|wezterm|foot|ghostty|konsole|gnome-terminal|xfce4-terminal|terminal|ssh) ]]
}

ydo_key() {
  if ! command -v ydotool >/dev/null 2>&1; then
    notify "Cannot paste" "ydotool is not installed."
    exit 1
  fi
  if ! ydotool key "$@" >/tmp/waybar-clipboard-ydotool.out 2>/tmp/waybar-clipboard-ydotool.err; then
    notify "Paste failed" "ydotool failed: $(cat /tmp/waybar-clipboard-ydotool.err 2>/dev/null)"
    exit 1
  fi
}

paste_keys() {
  # evdev: leftctrl=29, leftshift=42, v=47
  # Default to Ctrl+Shift+V because this button is primarily for terminals/SSH.
  # Many non-terminals also accept this as plain-text paste.
  sleep 0.12
  ydo_key 29:1 42:1 47:1 47:0 42:0 29:0
}

safe_paste() {
  local orig safe had_newline oldmime
  orig="$(get_clip)"
  if [[ -z "$orig" ]]; then
    notify "Clipboard is empty" "Nothing to paste."
    exit 0
  fi

  # Safety for terminals/SSH: remove trailing Enter and non-printing controls.
  # Internal newlines are kept, but bracketed-paste-aware shells should not execute them immediately.
  safe="$(printf '%s' "$orig" | python3 -c 'import re,sys
s=sys.stdin.read()
s=re.sub(r"[\r\n]+$", "", s)
s="".join(ch for ch in s if ch in "\n\t" or (32 <= ord(ch) != 127))
print(s, end="")')"
  had_newline=0
  if [[ "$safe" == *$'\n'* ]]; then
    had_newline=1
  fi

  if [[ "$safe" != "$orig" ]]; then
    oldmime="$(wl-paste --list-types 2>/dev/null | head -n1 || true)"
    printf '%s' "$safe" | wl-copy --type text/plain
    sleep 0.05
    paste_keys
    # Restore original clipboard shortly after the compositor/app consumes paste.
    ( sleep 0.6; printf '%s' "$orig" | wl-copy --type "${oldmime:-text/plain}" ) >/dev/null 2>&1 & disown || true
  else
    paste_keys
  fi

  if ((had_newline)); then
    notify "Pasted multiline clipboard" "Trailing Enter was stripped for terminal safety."
  fi
}

raw_paste() {
  if [[ -z "$(get_clip)" ]]; then
    notify "Clipboard is empty" "Nothing to paste."
    exit 0
  fi
  paste_keys
}

pick_history() {
  clipman pick --tool wofi --max-items 50 || true
}

case "${1:-status}" in
  status) json_status ;;
  paste) safe_paste ;;
  raw-paste) raw_paste ;;
  pick) pick_history ;;
  *) echo "usage: $0 {status|paste|raw-paste|pick}" >&2; exit 2 ;;
esac
