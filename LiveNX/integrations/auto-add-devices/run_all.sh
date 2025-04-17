
#!/bin/bash

# Change to the appropriate directory
cd /home/admin/liveaction-integrations/LiveNX/integrations/auto-add-devices

# Function to run a script in the background and restart it after 5 seconds if it exits
run_with_restart() {
    local script_name=$1
    
    while true; do
        echo "Starting $script_name..."
        sh ./$script_name
        
        echo "$script_name exited. Restarting in 5 seconds..."
        sleep 5
    done
}

# Run both scripts in separate background processes
run_with_restart "run_devices_and_interfaces.sh"

# Keep the main script running
echo "Both scripts are running in the background with auto-restart enabled."
echo "Press Ctrl+C to terminate all processes."
wait
