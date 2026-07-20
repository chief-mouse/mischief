"""Active-user identity: the single source of truth for who is acting.

An ``Identity`` bundles the four things every downstream layer needs — the
common name (the RBAC-facing handle), the certificate PEM, and the on-disk
paths to the cert and its matching private key. Nothing else in the codebase
should ever reconstruct a key filename from a CN; it reads ``key_path`` here.
"""

import os
import logging

from mschf.gen_cert import x509, NameOID, default_backend
from mschf.trust import resolve_trust_anchors, is_cert_trusted

log = logging.getLogger(__name__)

NO_ACCESS = "No Access"


class Identity:
    def __init__(self, cn, cert_path, key_path, cert_pem, is_valid,
                 identity_label, status_text):
        self.cn = cn
        self.cert_path = cert_path
        self.key_path = key_path
        self.cert_pem = cert_pem
        self.is_valid = is_valid
        self.identity_label = identity_label
        self.status_text = status_text
        # Passphrase to decrypt key_path for signing, held in memory only after a
        # successful login. None for plaintext keys or when not logged in.
        self.key_passphrase = None

    @staticmethod
    def _sibling_key_path(cert_path):
        """The private key lives next to the cert, sharing its basename."""
        stem, _ = os.path.splitext(cert_path)
        return stem + ".key"

    @classmethod
    def invalid(cls, identity_label, status_text):
        return cls(NO_ACCESS, None, None, "", False, identity_label, status_text)

    @classmethod
    def logged_out(cls):
        """The startup state: no one is authenticated yet, so nothing may open."""
        return cls.invalid(
            "Active Identity: None (not authenticated)",
            "Not authenticated — log in via the Auth Gateway to open apps.",
        )

    @classmethod
    def load(cls, cert_path, ca_cert_path=None, trust_dir=None):
        """Load a certificate, verify it chains to a trust anchor, and locate its key.

        ``ca_cert_path`` stays positional-compatible for existing callers.
        Trust is resolved via ``resolve_trust_anchors`` (host CA file + optional
        trust directory); an identity chaining to *any* anchor is valid.

        Returns a valid ``Identity`` on success, or a ``NO_ACCESS`` identity
        (with an explanatory ``status_text``) on any failure.
        """
        try:
            with open(cert_path, 'rb') as f:
                pem_cert = f.read()

            cert = x509.load_pem_x509_certificate(pem_cert, default_backend())
            try:
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                cn = "Unknown"

            anchors = resolve_trust_anchors(ca_cert_path, trust_dir)
            if not is_cert_trusted(pem_cert, anchors):
                log.warning(f"CRITICAL: identity certificate at {cert_path} is not signed by a trusted CA.")
                return cls.invalid(
                    f"Active Identity: {cn} (INVALID - NOT SIGNED BY CA)",
                    f"Error: Identity {cn} is not signed by Root CA. Denied.",
                )

            cert_pem = pem_cert.decode('utf-8') if isinstance(pem_cert, bytes) else pem_cert
            return cls(
                cn=cn,
                cert_path=cert_path,
                key_path=cls._sibling_key_path(cert_path),
                cert_pem=cert_pem,
                is_valid=True,
                identity_label=f"Active Identity: {cn} ({os.path.basename(cert_path)} Loaded)",
                status_text=f"Switched active identity to {cn}.",
            )
        except Exception as e:
            log.error(f"Failed to load or verify certificate at {cert_path}: {e}")
            return cls.invalid(
                "Active Identity: None (Error Loading)",
                f"Error loading certificate: {e}",
            )
