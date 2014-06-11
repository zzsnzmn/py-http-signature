#!/usr/bin/env python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import unittest

from http_signature.verify import HeaderVerifier, Verifier
from http_signature.sign import HeaderSigner, Signer


class TestVerify(unittest.TestCase):
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
        self.private_key = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')
        self.public_key = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')

    def test_basic_sign(self):
        signer = Signer(secret=self.private_key)
        verifier = Verifier(public_key=self.public_key)

        # generate signed string
        signature = signer.sign("this is a test")
        self.assertTrue(verifier.verify(data="this is a test",
                                        signature=signature))
        self.assertFalse(verifier.verify(data="this is not the signature you were looking for...",
                                         signature=signature))

    # def test_signed_headers(self):
        # signer = HeaderSigner(secret=self.private_key)
        # verifier = HeaderVerifier(public_key=self.public_key)

    def test_default(self):
        # hs = HeaderSigner(key_id='fingerprint', secret=self.private_key)
        hv = HeaderVerifier(public_key=self.public_key)

        # unsigned = {
            # 'Date': 'Thu, 05 Jan 2012 21:31:40 GMT'
        # }
        # signed = hs.sign(unsigned)
        # self.assertIn('Date', signed)
        # self.assertEqual(unsigned['Date'], signed['Date'])
        # self.assertIn('Authorization', signed)
        # params = hv.parse_auth(signed['Authorization'])
        # self.assertIn('keyId', params)
        # self.assertIn('algorithm', params)
        # self.assertIn('signature', params)
        # self.assertEqual(params['keyId'], 'fingerprint')
        # self.assertEqual(params['algorithm'], 'rsa-sha256')
        # self.assertEqual(params['signature'], 'ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=')


        HOST = "example.com"
        METHOD = "POST"
        PATH = '/foo?param=value&pet=dog'
        hs = HeaderSigner(key_id='Test', secret=self.private_key, headers=[
            'request-line',
            'host',
            'date',
            'content-type',
            'content-md5',
            'content-length'
        ])
        unsigned = {
            'Host': HOST,
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT',
            'Content-Type': 'application/json',
            'Content-MD5': 'Sd/dVLAcvNLSq16eXua5uQ==',
            'Content-Length': '18',
        }
        signed = hs.sign(unsigned, method=METHOD,
                path=PATH)

        self.assertTrue(hv.verify_headers(signed, host=HOST, method=METHOD, path=PATH))


if __name__ == "__main__":
    unittest.main()

