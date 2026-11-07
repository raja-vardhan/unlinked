#!/usr/bin/env bash
# Stops every role of the demo. Safe to run when nothing is running.
set -uo pipefail
cd "$(dirname "$0")/.."

stopped=0
for file in data/pids/*.pid; do
  [ -e "$file" ] || continue
  pid="$(cat "$file")"
  # Only signal a process that is still one of ours, in case its PID was reused.
  if ps -p "$pid" -o command= 2>/dev/null | grep -q 'unlinked --role'; then
    kill "$pid" 2>/dev/null && stopped=$((stopped + 1))
  fi
  rm -f "$file"
done
echo "Stopped $stopped running roles."
