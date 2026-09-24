"""Bounded TCP inventory. No open port is automatically a vulnerability."""
import shutil
import subprocess
import time
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from scanner.http_scanner import connect_ip

SERVICES = {80: 'http', 443: 'https', 8000: 'http-alt', 8080: 'http-proxy', 8443: 'https-alt', 5000: 'http-alt'}


def run(ctx):
    target = ctx['target']
    ports = sorted(set([target.port, 80, 443, 8000, 8080, 8443]))
    address = target.addresses[0]
    nmap = shutil.which('nmap')
    warning = None
    if nmap:
        args = [nmap, '-sT', '-sV', '--version-light', '-Pn', '-n', '--max-retries', '1', '--host-timeout', '15s', '-p', ','.join(map(str, ports)), '-oX', '-']
        if ':' in address:
            args.append('-6')
        args.append(address)
        try:
            output = subprocess.run(args, capture_output=True, timeout=min(18, ctx['client'].end - time.monotonic()), check=True)
            root = ET.fromstring(output.stdout)
            result = []
            for port in root.findall('.//port'):
                if port.find('state').get('state') == 'open':
                    service = port.find('service')
                    result.append({'port': int(port.get('portid')), 'protocol': port.get('protocol'), 'service': service.get('name', 'unknown') if service is not None else 'unknown', 'version': ' '.join(service.get(k, '') for k in ('product','version'))[:120] if service is not None else ''})
            if not root.findall('.//host'):
                warning = 'Nmap returned no host inventory; using TCP fallback.'
            else:
                return {'method':'Nmap TCP connect/version-light', 'address':address, 'tested_ports':ports, 'open_ports':result}
        except (OSError, subprocess.SubprocessError, ET.ParseError, DefusedXmlException, AttributeError, ValueError):
            warning = 'Nmap failed or timed out; using TCP fallback.'
    else:
        warning = 'Nmap is not installed. Bounded TCP connect inventory used; versions are unavailable.'
    result = []
    for port in ports:
        try:
            sock = connect_ip(address, port, min(.6, ctx['client'].remaining()))
            sock.close()
            result.append({'port':port, 'protocol':'tcp', 'service':SERVICES.get(port, 'unknown') + ' (port convention; unverified)', 'version':''})
        except OSError:
            pass
    return {'method':'TCP connect fallback', 'warning':warning, 'address':address, 'tested_ports':ports, 'open_ports':result}
