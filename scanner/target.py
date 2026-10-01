"""SSRF-aware validation with an immutable DNS snapshot used for every connection."""
from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote
import dns.resolver
from integrations.resolver import system_addresses
from analysis.redaction import redact_text


class TargetError(ValueError):
    pass


def safe_url(url):
    p = urlsplit(url)
    return redact_text(urlunsplit((p.scheme, p.netloc, p.path, urlencode([(k, '[redacted]') for k, _ in parse_qsl(p.query, keep_blank_values=True)]), '')))


def check_ip(value, allow_private):
    ip = ipaddress.ip_address(value)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or (ip.is_reserved and not ip.is_loopback) or str(ip) in ('100.100.100.200', 'fd00:ec2::254'):
        raise TargetError('Link-local, metadata, multicast, unspecified and reserved addresses are blocked.')
    labs = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') if ip.version == 4 else ('fc00::/7',)
    local = ip.is_loopback or any(ip in ipaddress.ip_network(network) for network in labs)
    if not ip.is_global and not (allow_private and local):
        raise TargetError('Local/private addresses require the local lab option; other non-public ranges are blocked.')
    return str(ip)


@dataclass(frozen=True)
class Target:
    url: str
    host: str
    port: int
    scheme: str
    addresses: tuple
    dns: dict
    allow_private: bool

    @property
    def display(self):
        return safe_url(self.url)

    def permits(self, url):
        try:
            p = urlsplit(url)
            port = p.port if p.port is not None else (443 if p.scheme == 'https' else 80)
            return (p.username is None and p.password is None and p.hostname == self.host and
                    ((p.scheme == self.scheme and port == self.port) or
                     (self.scheme == 'http' and p.scheme == 'https' and port == 443)))
        except ValueError:
            return False


def validate_target(raw, allow_private=False):
    if not isinstance(raw, str) or not raw or len(raw) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in raw) or '\\' in raw:
        raise TargetError('Enter a URL of at most 2,048 characters without whitespace or control characters.')
    try:
        p = urlsplit(raw)
        if p.scheme not in ('http', 'https') or not p.hostname or p.username is not None or p.password is not None:
            raise TargetError('Use an HTTP or HTTPS URL without embedded credentials.')
        # Fragments are browser-only; URL reconstruction below omits them.
        host = p.hostname.encode('idna').decode('ascii').lower().rstrip('.')
        port = p.port if p.port is not None else (443 if p.scheme == 'https' else 80)
        if not 1 <= port <= 65535 or p.netloc.endswith(':'):
            raise TargetError('Invalid port.')
        if '%' in host:
            raise TargetError('Encoded hosts and IPv6 zone identifiers are blocked.')
        try:
            numeric = ipaddress.ip_address(host)
        except ValueError:
            numeric = None
        if numeric is None:
            if len(host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
                raise TargetError('Invalid hostname.')
            if re.fullmatch(r'[0-9.]+', host) or host.startswith('0x'):
                raise TargetError('Ambiguous numeric addresses are blocked.')
        info = {'A': [], 'AAAA': [], 'CNAME': [], 'errors': []}
        if numeric:
            addresses = [str(numeric)]
            info['A' if numeric.version == 4 else 'AAAA'] = addresses.copy()
            info['note'] = 'IP literal; no DNS lookup needed.'
        elif host == 'localhost':
            addresses = ['127.0.0.1']
            info['A'] = addresses.copy()
            info['note'] = 'localhost is pinned to IPv4 loopback.'
        else:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 3
            for record in ('A', 'AAAA', 'CNAME'):
                try:
                    answer = resolver.resolve(host, record, lifetime=3, search=False)
                    info[record] = [str(r).rstrip('.') for r in answer][:16]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
                except dns.exception.DNSException:
                    info['errors'].append(record + ' lookup unavailable')
            addresses = info['A'] + info['AAAA']
            if not addresses:
                try:
                    addresses=system_addresses(host,port)
                except OSError:
                    raise TargetError('Both direct DNS and the system resolver failed. Check this Mac’s network/VPN/DNS connection and retry.') from None
                info['A']=[address for address in addresses if ':' not in address]
                info['AAAA']=[address for address in addresses if ':' in address]
                info['note']='Using the system resolver because direct DNS returned no addresses; all returned addresses are validated and pinned.'
        for address in addresses:
            check_ip(address, allow_private)
        authority = '[' + host + ']' if ':' in host else host
        if port != (443 if p.scheme == 'https' else 80):
            authority += ':' + str(port)
        path = quote(p.path or '/', safe="/%:@!$&'()*+,;=-._~")
        query = quote(p.query, safe="%=&+/:?@!$'()*,-._~")
        url = urlunsplit((p.scheme, authority, path, query, ''))
        if len(parse_qsl(query, keep_blank_values=True, max_num_fields=30)) > 20:
            raise TargetError('Use no more than 20 query parameters.')
        return Target(url, host, port, p.scheme, tuple(addresses), info, allow_private)
    except (ValueError, UnicodeError) as error:
        if isinstance(error, TargetError):
            raise
        raise TargetError('Malformed URL, hostname, port or query string.') from None
