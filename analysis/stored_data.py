"""Read-only validation of stored observations and comparison identity metadata."""
import json
import re


class StoredDataError(ValueError):
    """Persisted content is unavailable; never substitute empty scan results."""


def object_json(raw):
    def invalid_constant(value):
        raise ValueError()
    try:
        value=json.loads(raw,parse_constant=invalid_constant)
        if not isinstance(value,dict):raise ValueError()
        return value
    except (ValueError,TypeError,RecursionError):
        raise StoredDataError('Stored data is unavailable or malformed.') from None


def logical_fingerprint(raw):
    """Absent metadata supports legacy matching; malformed present fields do not."""
    value=object_json(raw)
    for key in ('finding_context','analysis'):
        if key not in value:return None
        value=value[key]
        if not isinstance(value,dict):raise StoredDataError('Stored comparison evidence is malformed.')
    fingerprint=value.get('logical_fingerprint')
    if fingerprint is not None and (not isinstance(fingerprint,str) or not re.fullmatch(r'[a-f0-9]{64}',fingerprint)):
        raise StoredDataError('Stored comparison identity is malformed.')
    return fingerprint
