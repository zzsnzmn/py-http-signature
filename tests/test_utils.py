#!/usr/bin/env python
import os
import re
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import unittest

from http_signature.utils import get_fingerprint

class TestUtils(unittest.TestCase):

    def test_get_fingerprint(self):
        with open('rsa_public.pem', 'r') as k:
            key = k.read()
        fingerprint = get_fingerprint(key)
        self.assertEqual(fingerprint, "73:61:a2:21:67:e0:df:be:7e:4b:93:1e:15:98:a5:b7")

        with open('test.pub', 'r') as k:
            key = k.read()
        fingerprint = get_fingerprint(key)
        self.assertEqual(fingerprint, "b3:d0:ad:c2:0e:a0:0f:3d:26:f1:67:3e:8b:91:9b:1a")


if __name__ == "__main__":
    unittest.main()
