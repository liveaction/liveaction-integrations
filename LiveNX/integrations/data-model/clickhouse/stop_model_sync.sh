#!/bin/bash

PID_FILE="integration_pids.txt"

if [ ! -f "$PID_FILE" ]; then
    echo "PID file not found: $PID_FILE"
    echo "Are the processes running?"
    exit 1
fi

# Read PIDs from file
read -r inventory_pid sites_pid alerts_pid < "$PID_FILE"

# Function to safely stop a process
stop_process() {
    local pid=$1
    local name=$2

    if ps -p "$pid" > /dev/null; then
        echo "Stopping $name process (PID: $pid)..."
        kill "$pid"

        # Wait up to 10 seconds for process to stop gracefully
        for i in {1..10}; do
            if ! ps -p "$pid" > /dev/null; then
                echo "$name process stopped successfully"
                return 0
            fi
            sleep 1
        done

        # Force kill if process hasn't stopped
        echo "$name process didn't stop gracefully, force killing..."
        kill -9 "$pid" 2>/dev/null || echo "Process $pid already terminated"
    else
        echo "$name process (PID: $pid) is not running"
    fi
}

# Stop all processes
stop_process "$inventory_pid" "inventory"
stop_process "$sites_pid" "sites"
stop_process "$alerts_pid" "alerts"

# Remove PID file
rm -f "$PID_FILE"
echo "All integration processes stopped and PID file removed"