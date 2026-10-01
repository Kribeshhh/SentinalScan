"""Bounded native DNS lookup: respect system/VPN resolver configuration."""
import socket
import threading

_slots=threading.BoundedSemaphore(4)


def system_addresses(host,port,seconds=5):
    if not _slots.acquire(blocking=False):raise OSError('System resolver busy')
    done=threading.Event();result=[];errors=[]
    def resolve():
        try:
            for row in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM):
                address=row[4][0]
                if address not in result:result.append(address)
        except OSError as exc:errors.append(exc)
        finally:_slots.release();done.set()
    threading.Thread(target=resolve,daemon=True,name='sentinelscan-dns').start()
    if not done.wait(seconds):raise TimeoutError('System DNS lookup timed out')
    if errors or not result:raise OSError('System DNS lookup failed')
    if len(result)>32:raise OSError('Too many DNS addresses')
    return result
