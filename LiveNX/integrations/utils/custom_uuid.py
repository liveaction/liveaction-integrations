import uuid


def is_valid_uuid(input_string):
    """
    To check if string is valid uuid or not
    """
    try:
        # Try to create a UUID object from the string
        uuid_obj = uuid.UUID(input_string)
        # If it works, it's a valid UUID
        return True
    except ValueError:
        # If a ValueError is raised, it's not a valid UUID
        return False