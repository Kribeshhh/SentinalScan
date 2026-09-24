"""Bounded GET-only transport: pinned IPs, verified TLS, same-host redirects, no cookies/proxies."""
from dataclasses import dataclass
import http.client
import os
import socket
import ssl
import time
import threading
from urllib.parse import urlsplit, urljoin
from scanner.target import safe_url


class ScanLimit(Exception):
    pass


class RequestFailure(Exception):
    pass


@dataclass
class Response:
    url: str
    status: int
    headers: list
    body: bytes
    truncated: bool
    redirects: list

    def header(self, name):
        return ', '.join(v for k, v in self.headers if k.lower() == name.lower())

    @property
    def text(self):
        return self.body.decode('utf-8', errors='replace')

    @property
    def html(self):
        return 'text/html' in self.header('Content-Type').lower()


def connect_ip(address, port, timeout):
    sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
        return sock
    except Exception:
        sock.close()
        raise


class Client:
    def __init__(self, target, timeout=4, max_bytes=262144, interval=.2, max_requests=60, deadline=150, cafile=None):
        self.target = target
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.interval = interval
        self.max_requests = max_requests
        self.end = time.monotonic() + deadline
        self.count = 0
        self.last = 0
        self.cafile = cafile

    def remaining(self):
        left = self.end - time.monotonic()
        if left <= 0:
            raise ScanLimit('Scan time budget reached')
        return min(left, self.timeout)

    def get(self, url, headers=None, redirects=True):
        chain = []
        for _ in range(5):
            if not self.target.permits(url):
                raise RequestFailure('Redirect outside authorized origin blocked')
            if self.count >= self.max_requests:
                raise ScanLimit('Request budget reached')
            time.sleep(min(max(0, self.interval - (time.monotonic() - self.last)), self.remaining()))
            self.remaining()
            self.count += 1
            self.last = time.monotonic()
            p = urlsplit(url)
            port = p.port or (443 if p.scheme == 'https' else 80)
            connection = None
            timer = None
            guard = None
            try:
                for address in self.target.addresses:
                    try:
                        sock = connect_ip(address, port, self.remaining())
                        break
                    except OSError:
                        sock = None
                if sock is None:
                    raise RequestFailure('Connection unavailable')
                if p.scheme == 'https':
                    try:
                        sock = ssl.create_default_context(cafile=self.cafile).wrap_socket(sock, server_hostname=self.target.host)
                    except Exception:
                        sock.close()
                        raise
                connection = http.client.HTTPConnection(self.target.host, port, timeout=self.remaining())
                connection.sock = sock
                # Enforce a wall-clock request cap even for a peer trickling headers/body.
                guard = socket.socket(fileno=os.dup(sock.fileno()))
                def interrupt(peer=guard):
                    try:
                        peer.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                timer = threading.Timer(self.remaining(), interrupt)
                timer.daemon = True
                timer.start()
                request_headers = {'Host': p.netloc, 'User-Agent': 'SentinelScan/5.0 (authorized assessment)', 'Accept-Encoding': 'identity', 'Connection': 'close'}
                request_headers.update(headers or {})
                connection.request('GET', p.path + ('?' + p.query if p.query else ''), headers=request_headers)
                response = connection.getresponse()
                body = bytearray()
                while len(body) <= self.max_bytes:
                    self.remaining()
                    chunk = response.read1(min(16384, self.max_bytes + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                result = Response(url, response.status, response.getheaders(), bytes(body[:self.max_bytes]), len(body) > self.max_bytes, chain.copy())
            except ssl.SSLCertVerificationError:
                raise RequestFailure('TLS certificate verification failed') from None
            except (OSError, http.client.HTTPException, ValueError):
                raise RequestFailure('HTTP request failed or timed out') from None
            finally:
                if timer:
                    timer.cancel()
                if guard:
                    guard.close()
                if connection:
                    connection.close()
            location = result.header('Location')
            if redirects and result.status in (301, 302, 303, 307, 308) and location:
                next_url = urljoin(url, location)
                allowed = self.target.permits(next_url) and not any(ord(c) < 32 for c in next_url)
                chain.append({'status': result.status, 'from': safe_url(url), 'to': safe_url(next_url) if allowed else '[out-of-scope redirect blocked]', 'followed': allowed})
                if not allowed:
                    result.redirects = chain
                    return result
                url = next_url
                continue
            result.redirects = chain
            return result
        raise RequestFailure('Redirect limit reached')


def observation(response):
    public = {'content-type', 'content-length', 'server', 'x-powered-by', 'content-security-policy', 'strict-transport-security', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy', 'access-control-allow-origin', 'access-control-allow-credentials', 'access-control-allow-methods', 'access-control-allow-headers'}
    # Arbitrary headers can contain secrets. Only selected configuration headers are retained.
    headers = {k: (v[:1000] if k.lower() in public else '[value omitted]') for k, v in response.headers if k.lower() != 'set-cookie'}
    return {'url': safe_url(response.url), 'status': response.status, 'headers': headers,
            'content_type': response.header('Content-Type')[:200], 'captured_bytes': len(response.body),
            'truncated': response.truncated, 'redirects': response.redirects,
            'https': response.url.startswith('https:'), 'server': response.header('Server')[:200]}
