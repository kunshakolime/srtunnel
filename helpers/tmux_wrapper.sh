#!/bin/bash
SESSION="${1:-dashboard}"
SESSION=$(echo "$SESSION" | sed 's/[^a-zA-Z0-9_-]//g')
if [ -z "$SESSION" ]; then
    SESSION="dashboard"
fi
exec tmux new-session -A -s "$SESSION"
