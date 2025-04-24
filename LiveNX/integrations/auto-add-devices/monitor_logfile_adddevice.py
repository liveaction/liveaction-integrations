import os
import subprocess
import time
import logging
import sys
import argparse

local_logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

# Set the directory to monitor
directory_to_monitor = "/data/livenx-server/data/log"

if not os.path.isdir(directory_to_monitor):
    local_logger.error(f"Directory to monitor does not exist: {directory_to_monitor}")
    exit(1)

# Function to run adddevice.py with the filename as an argument in the background
def run_adddevice(logfile, file_event_type):
    local_logger.debug(f"Processing file event type {file_event_type} in background: {logfile}")
    subprocess.Popen(["python3", "adddevice.py", "--logfile", logfile])

# Function to monitor the directory for new or modified files
def monitor_directory(continuous):
    file_cache = {}  # Cache to store file modification times
    while True:
        try:
            for filename in os.listdir(directory_to_monitor):
                if (filename.startswith("LivenxNode_") or filename.startswith("LivenxServer_")):
                    filepath = os.path.join(directory_to_monitor, filename)
                    last_modified = os.path.getmtime(filepath)

                    # Check if the file is new or modified
                    if filepath not in file_cache:
                        file_event_type = "New File" if filepath not in file_cache else "Modified File"
                        file_cache[filepath] = last_modified
                        run_adddevice(filepath, file_event_type)
            if continuous == False:
                local_logger.info("Stopping directory monitoring.")
                break

            time.sleep(300)  # Polling interval
        except KeyboardInterrupt:
            local_logger.info("Stopping directory monitoring.")
            break

def main(args):

    if args.autoaddinterfaces:
        from autoaddinterfaces import start_interface_monitor
        start_interface_monitor()

    # Check for existing files that match the pattern in the directory
    if args.autoadddevices:
        for filename in os.listdir(directory_to_monitor):
            if filename.startswith("LivenxServer_") and filename.endswith(".log"):
                run_adddevice(os.path.join(directory_to_monitor, filename), "Existing File")

        if args.continuous:
            # Start monitoring the directory
            # Start the directory monitoring in the background
            local_logger.info("Starting directory monitoring in the background...")
            monitor_directory(args.continuous)

    if args.continuous:
        # Keep the script running to monitor the directory
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            local_logger.info("Stopping directory monitoring.")
            exit(0)
    else:
        local_logger.info("Directory monitoring is not continuous. Exiting.")
        exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor LiveNX log files for new devices")
    parser.add_argument("--autoaddinterfaces", action="store_true", help="Auto add interfaces")
    parser.add_argument("--autoadddevices", action="store_true", help="Auto add devices")
    parser.add_argument('--continuous', action="store_true", help='Run it continuously')
    args = parser.parse_args()
    main(args)
