"""Process-local credentials. Cookies hold only random lookup handles, never tokens."""
from collections import OrderedDict
import secrets
import threading


class CredentialStore:
    def __init__(self, capacity=32):
        self._tokens = OrderedDict()
        self._lock = threading.Lock()
        self.capacity = capacity

    def put(self, token):
        handle = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[handle] = token
            while len(self._tokens) > self.capacity:
                self._tokens.popitem(last=False)
        return handle

    def get(self, handle):
        with self._lock:
            return self._tokens.get(handle)

    def remove(self, handle):
        with self._lock:
            self._tokens.pop(handle, None)

    def __repr__(self):
        return '<CredentialStore credentials withheld>'
