#!/usr/bin/env bash
waybar_lock="/tmp/.lockfiles/waybar.lock"
function toggle {
/home/owner/scripts/waybar-toggle.sh &
}
function cleanup {
    pkill -SIGUSR1 waybar
}
trap cleanup SIGINT SIGTERM
if ! pgrep -x "waybar" > /dev/null;then
    waybar -c ~/.config/waybar/waybar.conf &
    toggle
fi

function handle {
    if [[ $1 == *"workspace"* || ${1:0:10} == "openwindow" || ${1:0:11} == "closewindow" || ${1:0:10} == "movewindow" ]]
    then
        workspace_id=$(hyprctl activewindow -j | jq ".workspace.id")
        non_floating_windows=$(hyprctl clients -j | jq "[.[] | select(.workspace.id == $workspace_id and .floating == false)] | length")
        if [[ $non_floating_windows -eq 0 || $non_floating_windows -gt 1 ]]
        then
            if [ -f "$waybar_lock" ]; then
            toggle
            fi
        elif [[ $non_floating_windows -eq 1 ]]
        then
            if [ ! -f "$waybar_lock" ]; then
            toggle
            fi
        fi
    fi
}

while true; do
    if socat - UNIX-CONNECT:/tmp/hypr/$(echo $HYPRLAND_INSTANCE_SIGNATURE)/.socket2.sock | while read line; do handle $line; done; then
        break
    else
        sleep 1
    fi
done
