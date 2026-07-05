#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <program invokation>"
    echo "Please provide application command as an argument."
    exit 1
fi
app="$1"
mkdir -p '/tmp/.lockfiles'
app_lock="/tmp/.lockfiles/$app.lock"

if [ ! -f "$app_lock" ]; then
    touch "$app_lock"
    "$app" >/dev/null 2>&1 &
else
    rm -rf "$app_lock"
    pkill -f "$app"
fi
echo ""{'tooltip': "$app"}"
