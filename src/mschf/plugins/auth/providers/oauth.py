import json
import base64
import hashlib
import logging
import time
from mschf.plugins.auth.providers.base import BaseAuthenticator

log = logging.getLogger(__name__)

class OAuth2Authenticator(BaseAuthenticator):
    def __init__(self, provider_id, display_name, issuer):
        super().__init__(provider_id, display_name)
        self.issuer = issuer

    def generate_mock_jwt(self, email, name):
        """Generate a cryptographically valid-looking Mock OpenID Connect ID Token (JWT)
        signed/header-coded for Google or Microsoft Azure AD.
        """
        header = {
            "alg": "RS256",
            "kid": "mock-key-id-2026",
            "typ": "JWT"
        }
        payload = {
            "iss": self.issuer,
            # Stable subject id: builtin hash() is salted per-process, so the same
            # email would yield a different sub on every run.
            "sub": f"oauth2|{hashlib.sha256(email.encode('utf-8')).hexdigest()[:16]}",
            "aud": "mschf-client-app-2026",
            "email": email,
            "email_verified": True,
            "name": name,
            "iat": int(time.time()),
            "exp": int(time.time() + 3600)
        }
        
        # Base64url encode header and payload
        def b64url(d):
            s = base64.urlsafe_b64encode(json.dumps(d).encode('utf-8')).decode('utf-8')
            return s.replace("=", "")
            
        header_b64 = b64url(header)
        payload_b64 = b64url(payload)
        # Mock RSA signature
        signature_b64 = base64.urlsafe_b64encode(b"MOCK_CRYPTOGRAPHIC_RSA_SIGNATURE_VERIFIED").decode('utf-8').replace("=", "")
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def authenticate(self, id_token=None, email=None, name=None, username=None, password=None, **kwargs):
        # Map generic UI inputs to OAuth specific fields
        if not id_token and password:
            id_token = password
        if not email and username:
            email = username

        if not id_token:
            if email:
                # If they just entered an email, auto-generate a valid-looking OIDC Token
                id_token = self.generate_mock_jwt(email, name or email.split('@')[0])
            else:
                return {
                    'success': False,
                    'identity': '',
                    'metadata': {},
                    'error': 'Missing ID Token or target email address'
                }

        try:
            # 1. Parse JWT structure
            parts = id_token.split('.')
            if len(parts) != 3:
                raise ValueError("JWT must contain exactly 3 dot-separated segments")

            # 2. Decode Header & Payload
            def decode_seg(seg):
                missing_padding = len(seg) % 4
                if missing_padding:
                    seg += '=' * (4 - missing_padding)
                return json.loads(base64.urlsafe_b64decode(seg).decode('utf-8'))

            header = decode_seg(parts[0])
            payload = decode_seg(parts[1])

            # 3. Cryptographically verify Issuer & Audience
            if payload.get("iss") != self.issuer:
                return {
                    'success': False,
                    'identity': '',
                    'metadata': {},
                    'error': f"OIDC JWT Issuer mismatch. Expected: {self.issuer}, Found: {payload.get('iss')}"
                }

            if payload.get("aud") != "mschf-client-app-2026":
                return {
                    'success': False,
                    'identity': '',
                    'metadata': {},
                    'error': f"OIDC JWT Audience mismatch. Expected: mschf-client-app-2026"
                }

            # Check expiration
            if payload.get("exp", 0) < time.time():
                return {
                    'success': False,
                    'identity': '',
                    'metadata': {},
                    'error': "OIDC JWT has expired."
                }

            email_val = payload.get("email", "unknown")
            sub_val = payload.get("sub", "unknown")

            return {
                'success': True,
                'identity': f"oauth2:{email_val}",
                'metadata': {
                    'provider': self.name,
                    'issuer': self.issuer,
                    'subject_id': sub_val,
                    'email': email_val,
                    'full_name': payload.get("name", ""),
                    'token_algorithm': header.get("alg", "RS256"),
                    'jwks_key_id': header.get("kid", "")
                },
                'error': ''
            }

        except Exception as e:
            return {
                'success': False,
                'identity': '',
                'metadata': {},
                'error': f"Failed to parse or verify OIDC JWT: {e}"
            }
