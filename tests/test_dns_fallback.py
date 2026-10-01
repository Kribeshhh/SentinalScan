import unittest
from unittest.mock import patch
import dns.exception
from scanner.target import validate_target,TargetError
from integrations.resolver import system_addresses
from integrations.network import request,RemoteError

class DNSFallbackTests(unittest.TestCase):
    def test_system_fallback_preserves_pinning_and_fragment_removal(self):
        with patch('scanner.target.dns.resolver.Resolver.resolve',side_effect=dns.exception.Timeout),patch('scanner.target.system_addresses',return_value=['93.184.216.34']):
            target=validate_target('https://example.com/#/')
        self.assertEqual(target.addresses,('93.184.216.34',))
        self.assertEqual(target.url,'https://example.com/')
        self.assertIn('system resolver',target.dns['note'])

    def test_system_fallback_does_not_bypass_ssrf_checks(self):
        for addresses in (['169.254.169.254'],['93.184.216.34','127.0.0.1']):
            with patch('scanner.target.dns.resolver.Resolver.resolve',side_effect=dns.exception.Timeout),patch('scanner.target.system_addresses',return_value=addresses),self.assertRaises(TargetError):
                validate_target('https://example.com/')

    def test_both_resolvers_failing_has_actionable_error(self):
        with patch('scanner.target.dns.resolver.Resolver.resolve',side_effect=dns.exception.Timeout),patch('scanner.target.system_addresses',side_effect=TimeoutError),self.assertRaisesRegex(TargetError,'system resolver failed'):
            validate_target('https://example.com/')

    def test_fixed_service_never_connects_to_private_dns_address(self):
        with patch('integrations.network.system_addresses',return_value=['127.0.0.1']),patch('integrations.network.socket.socket') as connect,self.assertRaises(RemoteError):
            request('api.github.com','/repos/owner/repo')
        connect.assert_not_called()

    def test_native_resolution_deduplicates(self):
        with patch('integrations.resolver.socket.getaddrinfo',return_value=[(2,1,6,'',('93.184.216.34',443))]*2):
            self.assertEqual(system_addresses('example.com',443),['93.184.216.34'])
