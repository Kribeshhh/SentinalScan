from datetime import datetime, timezone
import ssl
from urllib.parse import urlsplit
from cryptography import x509
from scanner.http_scanner import connect_ip
from scanner.common import issue


def run(ctx):
    target = ctx['target']
    response = ctx.get('response')
    effective = urlsplit(response.url if response else target.url)
    https = effective.scheme == 'https'
    port = (effective.port or 443) if https else 443
    result = {'port':port, 'https_target':https}
    if not https and response is not None and response.status not in (301,302,303,307,308):
        issue(ctx,'Website served over unencrypted HTTP','Low','Transport Security','The requested page was served over HTTP without an HTTPS upgrade.','Serve this resource over HTTPS and redirect HTTP requests to HTTPS.','High',observations={'tls':dict(result)})
    def handshake(verify):
        context = ssl.create_default_context(cafile=ctx['client'].cafile)
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        sock = connect_ip(target.addresses[0], port, ctx['client'].remaining())
        try:
            with context.wrap_socket(sock, server_hostname=target.host) as secure:
                return secure.getpeercert(binary_form=True), secure.version(), secure.cipher()
        finally:
            sock.close()
    try:
        der, version, cipher = handshake(True)
        result['verified'] = True
    except ssl.SSLCertVerificationError as error:
        reasons = {10:'expired',9:'not yet valid',62:'hostname mismatch',64:'IP address mismatch',18:'self-signed certificate',19:'self-signed certificate chain',20:'issuer unavailable',21:'chain verification failed'}
        reason = reasons.get(error.verify_code, 'certificate trust or identity verification failed')
        result.update(verified=False, verification_error=reason)
        issue(ctx,'TLS certificate validation failed','Medium','TLS', 'Certificate verification result: ' + reason + '.','Install a trusted, current certificate whose subject alternative names cover the hostname.','High',observations={'tls':dict(result)})
        try:
            # Certificate inspection only; no HTTP/application data on this unverified connection.
            der, version, cipher = handshake(False)
        except (OSError, ssl.SSLError):
            return result
    except (OSError, ssl.SSLError):
        result['available'] = False
        result['note'] = 'TLS endpoint unavailable or handshake failed. HTTP targets are probed on port 443 only.'
        return result
    certificate = x509.load_der_x509_certificate(der)
    expiry = certificate.not_valid_after_utc
    result.update(available=True, protocol=version, cipher=cipher[0], subject=certificate.subject.rfc4514_string(), issuer=certificate.issuer.rfc4514_string(), not_before=certificate.not_valid_before_utc.isoformat(), expires=expiry.isoformat())
    try:
        result['dns_names'] = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)[:30]
    except x509.ExtensionNotFound:
        result['dns_names'] = []
    days = (expiry - datetime.now(timezone.utc)).days
    result['days_remaining'] = days
    if 0 <= days <= 30:
        issue(ctx,'TLS certificate expires soon','Low','TLS',f'Certificate expires in {days} days.','Renew the certificate and verify automatic renewal.','High',observations={'tls':dict(result)})
    if version in ('TLSv1', 'TLSv1.1') or cipher[2] < 128:
        issue(ctx,'Weak negotiated TLS configuration','Medium','TLS','Negotiated protocol: ' + version + '; cipher: ' + cipher[0], 'Require TLS 1.2 or newer and modern cipher suites.','High',observations={'tls':dict(result)})
    result['coverage'] = 'One modern handshake; does not enumerate all supported protocols/ciphers.'
    return result
