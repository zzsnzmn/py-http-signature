#!/usr/bin/env python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import unittest

from http_signature.sign import HeaderSigner


class TestSign(unittest.TestCase):

    def _parse_auth(self, auth):
        """Basic Authorization header parsing."""
        # split 'Signature kvpairs'
        s, param_str = auth.split(' ', 1)
        self.assertEqual(s, 'Signature')
        # split k1="v1",k2="v2",...
        param_list = param_str.split(',')
        # convert into [(k1,"v1"), (k2, "v2"), ...]
        param_pairs = [p.split('=', 1) for p in param_list]
        # convert into {k1:v1, k2:v2, ...}
        param_dict = {k: v.strip('"') for k, v in param_pairs}
        return param_dict

    def setUp(self):
        self.key = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')

    def test_date_added(self):
        hs = HeaderSigner(key_id='', secret=self.key)
        unsigned = {}
        signed = hs.sign(unsigned)
        self.assertIn('Date', signed)
        self.assertIn('Authorization', signed)

    def test_default(self):
        hs = HeaderSigner(key_id='Test', secret=self.key)
        unsigned = {
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT'
        }
        signed = hs.sign(unsigned)
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        params = self._parse_auth(signed['Authorization'])
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['signature'], 'ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=')

    def test_all(self):
        hs = HeaderSigner(key_id='Test', secret=self.key, headers=[
            'request-line',
            'host',
            'date',
            'content-type',
            'content-md5',
            'content-length'
        ])
        unsigned = {
            'Host': 'example.com',
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT',
            'Content-Type': 'application/json',
            'Content-MD5': 'Sd/dVLAcvNLSq16eXua5uQ==',
            'Content-Length': '18',
        }
        signed = hs.sign(unsigned, method='POST',
                path='/foo?param=value&pet=dog')
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        params = self._parse_auth(signed['Authorization'])
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['headers'], 'request-line host date content-type content-md5 content-length')
        self.assertEqual(params['signature'], 'H/AaTDkJvLELy4i1RujnKlS6dm8QWiJvEpn9cKRMi49kKF+mohZ15z1r+mF+XiKS5kOOscyS83olfBtsVhYjPg2Ei3/D9D4Mvb7bFm9IaLJgYTFFuQCghrKQQFPiqJN320emjHxFowpIm1BkstnEU7lktH/XdXVBo8a6Uteiztw=')

if __name__ == '__main__':
    unittest.main()
