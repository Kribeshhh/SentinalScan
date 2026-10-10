"""Bounded loopback-only Ollama HTTP. No DNS, proxies, redirects or credentials."""
import http.client
import ipaddress
import os
import socket
import threading
from urllib.parse import urlsplit

from integrations.network import RemoteError, ResponseTooLarge


def endpoint(base):
    if not isinstance(base, str) or any(c.isspace() or ord(c) < 32 for c in base):
        raise ValueError('Invalid Ollama endpoint')
    try:
        url = urlsplit(base)
        host = url.hostname
        # Resolve localhost ourselves: never use DNS for the trusted local service.
        host = '127.0.0.1' if host == 'localhost' else host
        if (url.scheme != 'http' or url.username is not None or url.password is not None
                or url.path not in ('', '/') or url.query or url.fragment
                or '%' in (host or '') or not ipaddress.ip_address(host).is_loopback):
            raise ValueError()
        port = url.port if url.port is not None else 11434
        if not 1 <= port <= 65535:
            raise ValueError()
        return host, port
    except (ValueError, TypeError):
        raise ValueError('Ollama must use a trusted loopback HTTP endpoint') from None


def request(base, path, *, method='GET', body=None, limit=65536, seconds=20):
    host, port = endpoint(base)
    if (method, path) not in (('GET', '/api/tags'), ('POST', '/api/show'), ('POST', '/api/chat')):
        raise ValueError('Ollama request scope rejected')
    if body is not None and len(body) > 65536:
        raise ValueError('Ollama input exceeds limit')
    connection = http.client.HTTPConnection(host, port, timeout=min(3, seconds))
    timer = guard = None
    try:
        connection.connect()
        connection.sock.settimeout(seconds)
        guard = socket.socket(fileno=os.dup(connection.sock.fileno()))
        def interrupt():
            try:
                guard.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(seconds, interrupt)
        timer.daemon = True
        timer.start()
        connection.request(method, path, body=body, headers={
            'Content-Type': 'application/json', 'Accept-Encoding': 'identity', 'Connection': 'close'})
        response = connection.getresponse()
        data = bytearray()
        while len(data) <= limit:
            chunk = response.read1(min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise ResponseTooLarge('Ollama response exceeds limit')
        return response.status, dict(response.getheaders()), bytes(data)
    except (OSError, http.client.HTTPException):
        raise RemoteError('Local Ollama service unavailable or timed out') from None
    finally:
        if timer:
            timer.cancel()
        if guard:
            guard.close()
        connection.close()
