"""
Module to assist in verifying a signed header.
"""
from Crypto.Hash import SHA256, SHA, SHA512, HMAC
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from base64 import b64decode

from .utils import sig, is_rsa, CaseInsensitiveDict

ALGORITHMS = frozenset(['rsa-sha1', 'rsa-sha256', 'rsa-sha512', 'hmac-sha1', 'hmac-sha256', 'hmac-sha512'])
HASHES = {'sha1':   SHA,
          'sha256': SHA256,
          'sha512': SHA512}

class Verifier(object):
    """
    Verifies signed text against a public key.
    """
    def __init__(self, public_key='~/.ssh/id_rsa.pub', hash_algorithm="sha256"):
        with open(public_key, 'r') as k:
            key = k.read()
        self.rsa_key = RSA.importKey(key)
        self.signer = PKCS1_v1_5.new(self.rsa_key)
        self.hash_algorithm = HASHES[hash_algorithm]

    def verify(self, data, signature):
        """
        Checks data against the public key
        """
        digest = SHA256.new()
        # might need to b64 encode this
        digest.update(data)
        if self.signer.verify(digest, b64decode(signature)):
            return True
        elif self.signer.verify(digest, signature):
            return True
        else:
            return False


class HeaderVerifier(object):
    """
    Verifies an HTTP signature from given headers.
    """
    def __init__(self, public_key='~/.ssh/id_rsa.pub'):
        self.verifier = Verifier(public_key=public_key)

    def parse_auth(self, auth):
        """Basic Authorization header parsing."""
        # split 'Signature kvpairs'
        s, param_str = auth.split(' ', 1)
        # split k1="v1",k2="v2",...
        param_list = param_str.split(',')
        # convert into [(k1,"v1"), (k2, "v2"), ...]
        param_pairs = [p.split('=', 1) for p in param_list]
        # convert into {k1:v1, k2:v2, ...}
        param_dict = {k: v.strip('"') for k, v in param_pairs}
        return param_dict

    def get_signable(self, headers, method, path):
        """Get the string that is signed"""
        # if 'date' not in header_dict['headers']:
            # now = datetime.now()
            # stamp = mktime(now.timetuple())
            # header_dict['date'] = format_date_time(stamp)
        http_version = '1.1'
        header_dict = self.parse_auth(headers['authorization'])
        required_headers = header_dict['headers'].split(' ') or ['date']
        signable_list = []
        for h in required_headers:
            if h == 'request-line':
                if not method or not path:
                    raise Exception('method and path arguments required when using "request-line"')

                signable_list.append('%s %s HTTP/%s' %
                        (method.upper(), path, http_version))
            elif h == 'host':
                # 'host' special case due to requests lib restrictions
                # 'host' is not available when adding auth so must use a param
                # if no param used, defaults back to the 'host' header
                if not headers.get('host') :
                    if 'host' in header_dict:
                        host = headers[h]
                    else:
                        raise Exception('missing required header "%s"' % (h))
                # signable_list.append('%s: %s' % (h.lower(), host))
                signable_list.append('%s: %s' % (h.lower(), "example.com"))
            else:
                if h not in headers:
                    raise Exception('missing required header "%s"' % (h))

                signable_list.append('%s: %s' % (h.lower(), headers[h]))
        signable = '\n'.join(signable_list)
        return signable, header_dict['signature'], header_dict['keyId']

    def verify_headers(self, headers, host=None, method=None, path=None):
        headers = CaseInsensitiveDict(headers)
        signing_str, signature, key_id = self.get_signable(headers=headers, method=method, path=path)
        return self.verifier.verify(signing_str, signature)

