"""Real OpenID Connect authenticator (authorization code + PKCE, native/loopback flow).

Opens the system browser to the provider's authorize endpoint, catches the
redirect on a localhost HTTP server, exchanges the code for tokens, and verifies
the returned ID token's RS256 signature against the provider's JWKS. Uses only
the stdlib plus `cryptography` (already a dependency) — no extra packages.

Configuration is read from environment variables (e.g. MSCHF_GOOGLE_CLIENT_ID /
MSCHF_GOOGLE_CLIENT_SECRET). When unset, authenticate() returns a clear error and
the rest of the app keeps working. The blocking flow MUST be run off the UI thread.
"""

import os
import json
import time
import base64
import hashlib
import secrets
import logging
import webbrowser
import urllib.parse
import urllib.request
import urllib.error
import http.server

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

from mschf.plugins.auth.providers.base import BaseAuthenticator

log = logging.getLogger(__name__)


class OIDCError(Exception):
    pass


def _b64url_decode(data):
    if isinstance(data, str):
        data = data.encode('ascii')
    return base64.urlsafe_b64decode(data + b'=' * (-len(data) % 4))


def _b64url_uint(data):
    return int.from_bytes(_b64url_decode(data), 'big')


def make_pkce():
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii')
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')
    return verifier, challenge


def build_authorize_url(authorization_endpoint, client_id, redirect_uri, state, challenge,
                        scope="openid email profile", nonce=None):
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    if nonce:
        params["nonce"] = nonce
    return authorization_endpoint + "?" + urllib.parse.urlencode(params)


def verify_id_token(id_token, jwks, issuers, audience, nonce=None, now=None):
    """Verify an RS256 OIDC ID token against a JWKS. Return the claims or raise OIDCError."""
    now = int(time.time()) if now is None else now
    parts = id_token.split('.')
    if len(parts) != 3:
        raise OIDCError("malformed ID token")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    signature = _b64url_decode(parts[2])
    signing_input = (parts[0] + '.' + parts[1]).encode('ascii')

    if header.get('alg') != 'RS256':
        raise OIDCError(f"unexpected token alg {header.get('alg')!r} (expected RS256)")
    kid = header.get('kid')
    jwk = next((k for k in jwks.get('keys', []) if k.get('kid') == kid), None)
    if jwk is None:
        raise OIDCError("signing key (kid) not found in JWKS")
    public_key = rsa.RSAPublicNumbers(
        _b64url_uint(jwk['e']), _b64url_uint(jwk['n'])
    ).public_key(default_backend())
    try:
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise OIDCError("ID token signature verification failed")

    if payload.get('iss') not in issuers:
        raise OIDCError(f"unexpected issuer {payload.get('iss')!r}")
    aud = payload.get('aud')
    aud_list = aud if isinstance(aud, list) else [aud]
    if audience not in aud_list:
        raise OIDCError("audience mismatch")
    if int(payload.get('exp', 0)) < now:
        raise OIDCError("ID token expired")
    if nonce is not None and payload.get('nonce') != nonce:
        raise OIDCError("nonce mismatch")
    return payload


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if 'code' in query or 'error' in query:
            self.server.oidc_query = query
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(b"<html><body style='font-family:sans-serif'>"
                             b"<h2>Sign-in complete.</h2><p>You can close this tab and return to mschf.</p>"
                             b"</body></html>")
        else:
            # Ignore incidental requests (e.g. favicon) so they don't end the wait.
            self.send_response(204)
            self.end_headers()

    def log_message(self, *args):
        pass


def _http_get_json(url, timeout=15):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8'))


def _http_post_form(url, data, timeout=15):
    body = urllib.parse.urlencode(data).encode('ascii')
    req = urllib.request.Request(url, data=body,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        # Google returns error details in the body with a 4xx.
        try:
            return json.loads(e.read().decode('utf-8'))
        except Exception:
            raise


class OIDCAuthenticator(BaseAuthenticator):
    interactive = True  # the flow opens a browser and blocks; run it off the UI thread

    def __init__(self, provider_id, display_name, *, authorization_endpoint, token_endpoint,
                 jwks_uri, issuers, client_id_env, client_secret_env, identity_prefix="oauth2"):
        super().__init__(provider_id, display_name)
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.jwks_uri = jwks_uri
        self.issuers = issuers
        self.client_id_env = client_id_env
        self.client_secret_env = client_secret_env
        self.identity_prefix = identity_prefix

    def is_configured(self):
        return bool(os.environ.get(self.client_id_env))

    def _fail(self, msg):
        return {'success': False, 'identity': '', 'metadata': {}, 'error': msg}

    def authenticate(self, timeout=180, **kwargs):
        """Run the real interactive OIDC flow. Blocking — call off the UI thread."""
        client_id = os.environ.get(self.client_id_env)
        client_secret = os.environ.get(self.client_secret_env, "")
        if not client_id:
            return self._fail(
                f"{self.display_name} is not configured. Set {self.client_id_env} "
                f"(and {self.client_secret_env}) to a Google Cloud OAuth 'Desktop app' "
                f"client, then try again."
            )
        try:
            verifier, challenge = make_pkce()
            state = secrets.token_urlsafe(24)
            nonce = secrets.token_urlsafe(24)

            server = http.server.HTTPServer(('127.0.0.1', 0), _CallbackHandler)
            server.oidc_query = None
            server.timeout = 2
            redirect_uri = f"http://127.0.0.1:{server.server_address[1]}"

            auth_url = build_authorize_url(self.authorization_endpoint, client_id,
                                           redirect_uri, state, challenge, nonce=nonce)
            log.info(f"Opening browser for {self.display_name} sign-in at {self.authorization_endpoint}")
            webbrowser.open(auth_url)

            deadline = time.monotonic() + timeout
            while server.oidc_query is None and time.monotonic() < deadline:
                server.handle_request()
            server.server_close()

            query = server.oidc_query
            if not query:
                return self._fail("Timed out waiting for the browser sign-in to complete.")
            if 'error' in query:
                return self._fail(f"Authorization denied: {query['error'][0]}")
            if query.get('state', [None])[0] != state:
                return self._fail("State mismatch (possible CSRF) — sign-in aborted.")
            code = query.get('code', [None])[0]
            if not code:
                return self._fail("No authorization code returned by the provider.")

            token_resp = _http_post_form(self.token_endpoint, {
                'code': code,
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code',
                'code_verifier': verifier,
            })
            id_token = token_resp.get('id_token')
            if not id_token:
                detail = token_resp.get('error_description') or token_resp.get('error') or token_resp
                return self._fail(f"Token exchange failed: {detail}")

            jwks = _http_get_json(self.jwks_uri)
            claims = verify_id_token(id_token, jwks, self.issuers, client_id, nonce=nonce)

            email = claims.get('email', 'unknown')
            return {
                'success': True,
                'identity': f"{self.identity_prefix}:{email}",
                'metadata': {
                    'provider': self.name,
                    'issuer': claims.get('iss'),
                    'subject_id': claims.get('sub'),
                    'email': email,
                    'email_verified': claims.get('email_verified'),
                    'full_name': claims.get('name', ''),
                    'flow': 'authorization code + PKCE (real, signature-verified)',
                },
                'error': '',
            }
        except OIDCError as e:
            return self._fail(f"OIDC verification failed: {e}")
        except urllib.error.URLError as e:
            return self._fail(f"Network error during OIDC: {e}")
        except Exception as e:
            return self._fail(f"OIDC flow failed: {e}")
