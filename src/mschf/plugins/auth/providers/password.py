import hashlib
import os
import logging
from mschf.plugins.auth.providers.base import BaseAuthenticator

log = logging.getLogger(__name__)

class PasswordAuthenticator(BaseAuthenticator):
    def __init__(self):
        super().__init__("local_password", "Local User / PBKDF2 Password")
        # In-memory secure mock credential database using PBKDF2-SHA256
        # Pre-populate some mock corporate users:
        self.users = {}
        self.register_user("admin_user", "adminsecure2026")
        self.register_user("support_user", "supportsecure2026")

    def register_user(self, username, password):
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        self.users[username] = {
            'salt': salt,
            'key': key
        }

    def authenticate(self, username=None, password=None, **kwargs):
        if not username or not password:
            return {
                'success': False,
                'identity': '',
                'metadata': {},
                'error': 'Missing username or password'
            }

        user_record = self.users.get(username)
        if not user_record:
            return {
                'success': False,
                'identity': '',
                'metadata': {},
                'error': f"User '{username}' not found in PBKDF2 database"
            }

        salt = user_record['salt']
        expected_key = user_record['key']
        
        # Hash the input password using the same salt
        actual_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        
        # Constant-time comparison to prevent timing attacks
        if hmac_compare_digest(expected_key, actual_key):
            return {
                'success': True,
                'identity': f"user:{username}",
                'metadata': {
                    'auth_method': 'PBKDF2-HMAC-SHA256',
                    'username': username,
                    'hash_rounds': 100000
                },
                'error': ''
            }
        else:
            return {
                'success': False,
                'identity': '',
                'metadata': {},
                'error': 'Incorrect password'
            }

def hmac_compare_digest(a, b):
    # Safe comparison to mitigate timing attacks
    return hashlib.pbkdf2_hmac('sha256', a, b'\x00', 1) == hashlib.pbkdf2_hmac('sha256', b, b'\x00', 1)
