import time
from datetime import datetime, timedelta

def get_top_of_current_minute_epoch():
    # Get the current time
    now = datetime.now()
    
    # Reset seconds and microseconds to zero
    top_of_minute = now.replace(second=0, microsecond=0)
    
    # Convert to seconds past epoch
    epoch_time = int(top_of_minute.timestamp())
    
    return epoch_time