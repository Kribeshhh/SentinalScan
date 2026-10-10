"""Fixed-origin HTTPS with response limits, verified TLS and absolute request deadlines."""
import http.client
import os
import socket
import threading
import ssl
import time
import ipaddress
from integrations.resolver import system_addresses


class RemoteError(Exception):
    pass


class ResponseTooLarge(RemoteError):
    pass


def _request_once(host, path, method='GET', headers=None, body=None, limit=2_000_000, seconds=12):
    if host not in ('api.github.com', 'codeload.github.com', 'api.osv.dev') or not path.startswith('/') or any(ord(c)<32 for c in path):
        raise RemoteError('Remote request scope was rejected.')
    connection = http.client.HTTPSConnection(host, timeout=min(15,seconds))
    timer, guard = None, None
    phase="DNS resolution"
    raw=None
    try:
        addresses=system_addresses(host,443,seconds=min(5,seconds))
        if any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise RemoteError('Remote request scope rejected: service DNS returned a non-public address.')
        phase='TCP connection'
        end=time.monotonic()+min(15,seconds)
        for address in addresses:
            remaining=end-time.monotonic()
            if remaining<=0:break
            candidate=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_STREAM)
            candidate.settimeout(min(5,remaining))
            try:candidate.connect((address,443));raw=candidate;break
            except OSError:candidate.close()
        if raw is None:raise TimeoutError()
        phase='TLS handshake'
        raw.settimeout(min(15,seconds))
        connection.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=host)
        raw=None
        phase='HTTP response'
        guard = socket.socket(fileno=os.dup(connection.sock.fileno()))
        def interrupt():
            try:
                guard.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer=threading.Timer(seconds,interrupt);timer.daemon=True;timer.start()
        supplied={'User-Agent':'SentinelScan/5.0', 'Accept-Encoding':'identity', 'Connection':'close'}
        supplied.update(headers or {})
        connection.request(method,path,body=body,headers=supplied)
        response=connection.getresponse()
        data=bytearray()
        while len(data)<=limit:
            chunk=response.read1(min(65536,limit+1-len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data)>limit:
            raise ResponseTooLarge('Remote response exceeds the configured size limit.')
        return response.status, dict(response.getheaders()), bytes(data)
    except RemoteError:
        raise
    except ssl.SSLCertVerificationError:
        raise RemoteError('TLS certificate verification failed for the remote service. Check the system clock and trusted CA configuration.') from None
    except (OSError,http.client.HTTPException,ValueError):
        # Exception messages can contain authorization headers or signed archive URLs.
        raise RemoteError(host+': '+phase+' failed or timed out. Check network/VPN connectivity and retry. This is not a repository permission error.') from None
    finally:
        if timer:
            timer.cancel()
        if guard:
            guard.close()
        connection.close()
        if raw:raw.close()


def request(host,path,method='GET',headers=None,body=None,limit=2_000_000,seconds=12):
    """Retry transient read failures once; never replay a write or oversized response."""
    attempts=2 if method in ('GET','HEAD') else 1
    for attempt in range(attempts):
        try:
            result=_request_once(host,path,method,headers,body,limit,seconds)
            if result[0] not in (502,503,504) or attempt+1==attempts:return result
        except ResponseTooLarge:
            raise
        except RemoteError as exc:
            if attempt+1==attempts or 'TLS certificate' in str(exc) or 'scope' in str(exc):raise
        time.sleep(.3)
