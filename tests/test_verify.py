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
        verifier = Verifier(key_id=self.public_key)

        # generate signed string
        signature = signer.sign("this is a test")
        self.assertTrue(verifier.verify(data="this is a test",
                                        signature=signature))
        self.assertFalse(verifier.verify(data="this is not the signature you were looking for...",
                                         signature=signature))

    def test_default(self):
        # signer = HeaderSigner(secret=self.private_key)
        # verifier = HeaderVerifier(public_key=self.public_key)
        hs = HeaderSigner(key_id=self.public_key, secret=self.private_key)

        unsigned = {
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT'
        }
        signed = hs.sign(unsigned)
        hv = HeaderVerifier(headers=signed)
        self.assertTrue(hv.verify_headers())

    def test_signed_headers(self):
        HOST = "example.com"
        METHOD = "POST"
        PATH = '/foo?param=value&pet=dog'
        hs = HeaderSigner(key_id=self.public_key, secret=self.private_key, headers=[
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

        hv = HeaderVerifier(headers=signed, host=HOST, method=METHOD, path=PATH)
        self.assertTrue(hv.verify_headers())

    def test_incorrect_headers(self):
        HOST = "example.com"
        METHOD = "POST"
        PATH = '/foo?param=value&pet=dog'
        hs = HeaderSigner(secret=self.private_key,
                          key_id=self.public_key,
                          headers=[
                            'request-line',
                            'host',
                            'date',
                            'content-type',
                            'content-md5',
                            'content-length'])
        unsigned = {
            'Host': HOST,
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT',
            'Content-Type': 'application/json',
            'Content-MD5': 'Sd/dVLAcvNLSq16eXua5uQ==',
            'Content-Length': '18',
        }
        signed = hs.sign(unsigned, method=METHOD,
                path=PATH)

        hv = HeaderVerifier(headers=signed, required_headers=["some-other-header"], host=HOST, method=METHOD, path=PATH)
        with self.assertRaises(Exception) as ex:
            hv.verify_headers()
        self.assertEqual(ex.exception.message,
                        "some-other-header is a required header(s)")

    def test_extra_auth_headers(self):
        HOST = "example.com"
        METHOD = "POST"
        PATH = '/foo?param=value&pet=dog'
        hs = HeaderSigner(key_id=self.public_key, secret=self.private_key, headers=[
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
        hv = HeaderVerifier(headers=signed, method=METHOD, path=PATH,
                            required_headers=['date', 'request-line'])
        self.assertTrue(hv.verify_headers())

if __name__ == "__main__":
    unittest.main()

