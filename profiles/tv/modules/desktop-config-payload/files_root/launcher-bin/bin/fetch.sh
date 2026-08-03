#!/bin/bash
# Get the list of active workspaces
active_workspaces=$(hyprctl workspaces -j | jq -r '.[].id')
current_workspace=$(hyprctl monitors -j | jq -r '.[] | select(.focused == true) | .activeWorkspace.id')

# Iterate through each active workspace
for workspace in $active_workspaces; do
  # Skip the current workspace
  if [ "$workspace" == "$current_workspace" ]; then
    continue
  fi
windows=$(hyprctl clients -j | jq -r --arg ws "$workspace" '.[] | select(.workspace.id == ($ws|tonumber)) | .address')

  #attempt to focus and move every window to the current workspace
  for window in $windows; do
    hyprctl dispatch workspace "$workspace"
    hyprctl dispatch movefocus "$window"
    hyprctl dispatch movetoworkspace "$current_workspace"
  done
done
# Switch back to the current workspace
hyprctl dispatch workspace "$current_workspace"
