#!/usr/bin/env bash
set -euo pipefail

waybar_lock="/tmp/.lockfiles/waybar.lock"

function toggle {
    "$HOME/bin/waybar-toggle.sh" &
}

function cleanup {
    pkill -SIGUSR1 waybar || true
}
trap cleanup SIGINT SIGTERM

if ! pgrep -x "waybar" >/dev/null; then
    waybar -c ~/.config/waybar/waybar.conf &
    toggle
fi

function handle {
    local event="$1"
    if ! printf '%s' "$event" | jq -e 'has("change")' >/dev/null 2>&1; then
        return 0
    fi

    local workspace_json current_workspace current_output outputs_json active_count tree_json count
    workspace_json="$(swaymsg -t get_workspaces -r 2>/dev/null)" || return 0
    current_workspace="$(printf '%s' "$workspace_json" | jq -r '.[] | select(.focused == true) | .name' | head -n1)"
    current_output="$(printf '%s' "$workspace_json" | jq -r '.[] | select(.focused == true) | .output' | head -n1)"
    [[ -n "$current_workspace" && -n "$current_output" ]] || return 0

    outputs_json="$(swaymsg -t get_outputs -r 2>/dev/null)" || return 0
    active_count="$(printf '%s' "$outputs_json" | jq --arg output "$current_output" '[.[] | select(.name == $output and .active == true)] | length')"
    [[ "$active_count" == "1" ]] || return 0

    tree_json="$(swaymsg -t get_tree -r 2>/dev/null)" || return 0
    count="$(printf '%s' "$tree_json" | jq --arg workspace "$current_workspace" '
        def tiled_window_count:
            if .type == "con"
               and ((.nodes // []) | length) == 0
               and ((.floating_nodes // []) | length) == 0
               and (((.app_id // "") != "")
                    or ((.window_properties.class // "") != "")
                    or (.window != null))
            then 1
            else [(.nodes // [])[] | tiled_window_count] | add // 0
            end;
        [.. | objects
         | select(.type == "workspace" and .name == $workspace)
         | tiled_window_count] | add // 0
    ' 2>/dev/null)" || return 0
    [[ "$count" =~ ^[0-9]+$ ]] || return 0

    if [[ "$count" -eq 0 || "$count" -gt 1 ]]; then
        if [[ -f "$waybar_lock" ]]; then
            toggle
        fi
    elif [[ "$count" -eq 1 ]]; then
        if [[ ! -f "$waybar_lock" ]]; then
            toggle
        fi
    fi
}

while true; do
    if swaymsg -t subscribe -m '["workspace","window"]' | while IFS= read -r event; do
        handle "$event"
    done; then
        break
    else
        sleep 1
    fi
done
