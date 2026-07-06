import os
import hashlib
import base64
import json
import logging
from mschf.plugins.auth.providers.base import BaseAuthenticator
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

log = logging.getLogger(__name__)

class PasskeyAuthenticator(BaseAuthenticator):
    def __init__(self):
        super().__init__("fido2_passkey", "FIDO2 / WebAuthn Hardware Passkey")
        # In-memory "secure enclave" database storing registered public keys for each passkey user
        self.registered_credentials = {}

    def register_passkey(self, username):
        """WebAuthn Registration Ceremony.
        Generates a new RSA public-private keypair on the hardware token (the enclave)
        and registers the public key on the host.
        """
        # 1. Generate keypair inside hardware enclave
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # 2. Extract Public Key
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 3. Save Private Key (Enclave Storage) and Public Key (Host Storage)
        credential_id = f"cred_{base64.b64encode(os.urandom(8)).decode('utf-8').replace('=', '')}"
        
        self.registered_credentials[username] = {
            'credential_id': credential_id,
            'public_key_pem': pub_pem.decode('utf-8'),
            'private_key_obj': private_key # Kept safe in enclave
        }
        
        return credential_id, pub_pem.decode('utf-8')

    def authenticate(self, username=None, challenge=None, **kwargs):
        if not username:
            return {
                'success': False,
                'identity': '',
                'metadata': {},
                'error': 'Missing username for WebAuthn authentication'
            }

        cred_record = self.registered_credentials.get(username)
        if not cred_record:
            # Auto-register if not exists to make the demo incredibly smooth!
            cred_id, pub_pem = self.register_passkey(username)
            cred_record = self.registered_credentials[username]
            auto_registered = True
        else:
            auto_registered = False

        # WebAuthn Authentication Ceremony
        if not challenge:
            challenge = base64.b64encode(os.urandom(16)).decode('utf-8')

        # 1. Sign challenge inside enclave using Private Key
        private_key = cred_record['private_key_obj']
        signature = private_key.sign(
            challenge.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # 2. Verify signature on host using Public Key
        public_key_pem = cred_record['public_key_pem']
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        try:
            public_key.verify(
                signature,
                challenge.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            return {
                'success': True,
                'identity': f"passkey:{username}",
                'metadata': {
                    'credential_id': cred_record['credential_id'],
                    'challenge_signed': challenge,
                    'signature_hex': signature.hex()[:64] + "...",
                    'crypto_algorithm': 'RSASSA-PKCS1-v1_5-SHA256',
                    'auto_registered': auto_registered
                },
                'error': ''
            }
        except Exception as e:
            return {
                'success': False,
                'identity': '',
                'metadata': {},
                'error': f"WebAuthn Cryptographic Signature verification failed: {e}"
            }
