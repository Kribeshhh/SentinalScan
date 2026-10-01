"""Fixed-origin HTTPS with response limits, verified TLS and absolute request deadlines."""
import http.client
import os
import socket
import threading


class RemoteError(Exception):
    pass


class ResponseTooLarge(RemoteError):
    pass


def request(host, path, method='GET', headers=None, body=None, limit=2_000_000, seconds=12):
    if host not in ('api.github.com', 'codeload.github.com', 'api.osv.dev') or not path.startswith('/') or any(ord(c)<32 for c in path):
        raise RemoteError('Remote request scope was rejected.')
    connection = http.client.HTTPSConnection(host, timeout=min(5,seconds))
    timer, guard = None, None
    try:
        connection.connect()
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
    except (OSError,http.client.HTTPException,ValueError):
        # Exception messages can contain authorization headers or signed archive URLs.
        raise RemoteError('Remote service is unavailable or the request timed out.') from None
    finally:
        if timer:
            timer.cancel()
        if guard:
            guard.close()
        connection.close()
