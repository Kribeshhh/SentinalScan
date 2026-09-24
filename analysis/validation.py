"""Bounds shared by HTTP handlers before binding identifiers to SQLite."""
SQLITE_MAX_ID = 2**63 - 1


def record_id(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError('Invalid record identifier.') from None
    if not 1 <= number <= SQLITE_MAX_ID:
        raise ValueError('Invalid record identifier.')
    return number
