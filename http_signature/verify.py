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
    def __init__(self, key_id='~/.ssh/id_rsa.pub', hash_algorithm="sha256"):
        self.rsa_key = self._get_key(key_id)
        self.signer = PKCS1_v1_5.new(self.rsa_key)
        self.hash_algorithm = HASHES[hash_algorithm]

    def _get_key(self, key_id):
        with open(key_id, 'r') as k:
            key = k.read()
        return RSA.importKey(key)


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


class HeaderVerifier(Verifier):
    """
    Verifies an HTTP signature from given headers.
    """
    def __init__(self, headers, required_headers=None, method=None, path=None,
                 host=None, http_version='1.1', key_id='~/.ssh/id_rsa.pub'):
        super(HeaderVerifier, self).__init__(key_id=key_id, hash_algorithm="sha256")

        required_headers = required_headers or ['date']
        self.auth_dict = self.parse_auth(headers['authorization'])
        self.headers = CaseInsensitiveDict(headers)
        self.required_headers = [s.lower() for s in required_headers]
        self.http_version = http_version
        self.method = method
        self.path = path
        self.host = host

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


    def get_signable(self):
        """Get the string that is signed"""
        header_dict = self.parse_auth(self.headers['authorization'])
        if self.auth_dict.get('headers'):
            auth_headers = self.auth_dict.get('headers').split(' ')
        else:
            auth_headers = ['date']

        if len(set(self.required_headers) - set(auth_headers)) > 0:
            raise Exception('{} is a required header(s)'.format(', '.join(set(self.required_headers)-set(auth_headers))))

        signable_list = []
        for h in auth_headers:
            if h == 'request-line':
                if not self.method or not self.path:
                    raise Exception('method and path arguments required when using "request-line"')

                signable_list.append('%s %s HTTP/%s' %
                        (self.method.upper(), self.path, self.http_version))
            elif h == 'host':
                # 'host' special case due to requests lib restrictions
                # 'host' is not available when adding auth so must use a param
                # if no param used, defaults back to the 'host' header
                if not self.headers.get('host') :
                    if 'host' in header_dict:
                        host = self.headers[h]
                    elif self.host:
                       signable_list.append('%s: %s' % (h.lower(), self.host))
                    else:
                        raise Exception('missing required header "%s"' % (h))
                signable_list.append('%s: %s' % (h.lower(), self.headers[h]))
            else:
                if h not in self.headers:
                    raise Exception('missing required header "%s"' % (h))

                signable_list.append('%s: %s' % (h.lower(), self.headers[h]))
        signable = '\n'.join(signable_list)
        return signable

    def verify_headers(self):
        signing_str = self.get_signable()
        # self.auth_dict['keyId']
        # self.auth_dict['signature']
        return self.verify(signing_str, self.auth_dict['signature'])
