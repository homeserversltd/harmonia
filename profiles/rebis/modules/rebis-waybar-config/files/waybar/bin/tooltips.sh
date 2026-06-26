#!/bin/sh

case "$1" in
  "usb")
    echo '{"text": "󰕓", "tooltip": "Drive Management"}'
    ;;
  "printer")
    echo '{"text": "󰐪", "tooltip": "Printer Management"}'
    ;;
  "fetch")
    echo '{"text": "", "tooltip": "Fetches all windows to current workspace"}'
    ;;
  *)
    echo '{"text": "Invalid argument", "tooltip": "Invalid argument"}'
    ;;
esac
