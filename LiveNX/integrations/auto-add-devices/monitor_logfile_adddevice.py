import os
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import logging
import sys

local_logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

# Set the directory to monitor
directory_to_monitor = "/data/livenx-server/data/log"

if not os.path.isdir(directory_to_monitor):
    local_logger.error(f"Directory to monitor does not exist: {directory_to_monitor}")
    exit(1)

# Function to run adddevice.py with the filename as an argument in the background
def run_adddevice(logfile, file_event_type):
    local_logger.info(f"Processing file event type {file_event_type} in background: {logfile}")
    subprocess.Popen(["python3", "adddevice.py", "--logfile", logfile])

# Custom event handler to monitor file creation
class LogFileHandler(FileSystemEventHandler):
    file_cache = {} ## store modified file with time
    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.startswith(os.path.join(directory_to_monitor, "LivenxServer_")) and event.src_path.endswith(".log"):
            run_adddevice(event.src_path, "New File")
    
    def on_modified(self, event):

        ## delete keys older than 3 sec
        older_keys = []
        for key in self.file_cache:
            seconds = int(time.time())
            if seconds - key[0] > 3:
                older_keys.append(key)
        for key in older_keys:
            del self.file_cache[key]
        if event.is_directory:
            return
        
        if event.src_path.startswith(os.path.join(directory_to_monitor, "LivenxServer_")) and event.src_path.endswith(".log"):
            seconds = int(time.time())
            key = (seconds, event.src_path)
            if key in self.file_cache:
                return
            self.file_cache[key] = True
            run_adddevice(event.src_path, "Modified File")

# Set up observer and event handler
observer = Observer()
event_handler = LogFileHandler()

# Monitor the directory and start observer
observer.schedule(event_handler, path=directory_to_monitor, recursive=False)
observer.start()

try:
    # Check for existing files that match the pattern in the directory
    for filename in os.listdir(directory_to_monitor):
        if filename.startswith("LivenxServer_") and filename.endswith(".log"):
            run_adddevice(os.path.join(directory_to_monitor, filename), "Existing File")
    
    # Keep the observer running
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()

observer.join()