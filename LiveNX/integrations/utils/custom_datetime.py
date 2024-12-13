import re

def is_valid_iso_datetime(date_string):
    """
    To check if string is valid uuid or not
    """
    iso_pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
    try:
        # If iso_datetime valid return True/False
        return re.match(iso_pattern, date_string)
    except Exception as e:
        # Error for match
        return False