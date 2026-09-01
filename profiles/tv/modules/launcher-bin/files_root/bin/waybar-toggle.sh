#!/bin/bash
mkdir -p '/tmp/.lockfiles'
waybar_lock="/tmp/.lockfiles/waybar.lock"

if [ ! -f "$waybar_lock" ]; then
    touch "$waybar_lock"
    pkill -SIGUSR1 waybar
else
    rm -rf "$waybar_lock"
    pkill -SIGUSR1 waybar
fi
