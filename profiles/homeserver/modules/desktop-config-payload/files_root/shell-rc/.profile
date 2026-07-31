if command -v tmux >/dev/null 2>&1 && [ -z "$TMUX" ]; then
       # Start a new tmux session or attach to an existing one named "default"
       tmux attach-session -t default || tmux new-session -s default
fi

# Check and mount vault if needed
if [ -f "/usr/local/sbin/mountvault.sh" ]; then
    # Create a flag file in /run to track per-boot execution
    flag_file="/run/user/$(id -u)/vault_mounted"
    flag_dir="$(dirname "$flag_file")"
    
    if [ ! -f "$flag_file" ] && ! mountpoint -q /vault; then
        echo "Mount script has not run this boot cycle. Running now..."
        sudo /usr/local/sbin/mountvault.sh && mkdir -p "$(dirname "$flag_file")" && touch "$flag_file"
    fi
fi

. "$HOME/.atuin/bin/env"
