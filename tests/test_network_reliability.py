import unittest
from unittest.mock import patch
from integrations.network import request,RemoteError,ResponseTooLarge
from scanner.target import validate_target

class NetworkReliabilityTests(unittest.TestCase):
    def test_browser_fragment_is_not_sent_or_persisted(self):
        target=validate_target('http://127.0.0.1:8000/#/search?secret=hidden',True)
        self.assertEqual(target.url,'http://127.0.0.1:8000/')
        self.assertNotIn('hidden',target.display)

    def test_read_retries_transient_failures_once(self):
        for failure in (RemoteError('Remote service is unavailable or the request timed out.'),(503,{},b'')):
            with patch('integrations.network._request_once',side_effect=[failure,(200,{},b'ok')]) as call,patch('integrations.network.time.sleep'):
                self.assertEqual(request('api.github.com','/repos/owner/repo')[0],200)
                self.assertEqual(call.call_count,2)

    def test_writes_tls_and_size_failures_are_not_retried(self):
        for method,error in [('POST',RemoteError('timeout')),('GET',ResponseTooLarge('size')),('GET',RemoteError('TLS certificate verification failed'))]:
            with patch('integrations.network._request_once',side_effect=error) as call,self.assertRaises(RemoteError):
                request('api.github.com','/repos/owner/repo',method=method)
            self.assertEqual(call.call_count,1)
