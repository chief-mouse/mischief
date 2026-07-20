"""Host trust anchors: the local Root CA plus an optional directory of org CAs.

Signature verification and identity loading accept certificates that chain to
*any* resolved anchor. Anchors are re-resolved on every check so a cert added
to the trust directory after a container is opened is picked up immediately.

Do not import ``mschf.storage`` here — storage imports this module.
"""

import hashlib
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from mschf.gen_cert import is_cert_signed_by_ca

# Same HOST_ROOT derivation as storage.py (abspath of ../.. from this module).
HOST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_CA_CERT_PATH = os.path.join(HOST_ROOT, "ca.crt")
DEFAULT_TRUST_DIR = os.path.join(HOST_ROOT, "trusted_cas")


def resolve_trust_anchors(ca_cert_path=None, trust_dir=None):
    """Load trusted CA certificate PEMs from the host CA file and trust directory.

    Returns a de-duplicated list of PEM bytes (one entry per unique DER). An
    empty list is legal — callers must fail closed.
    """
    candidate_file = ca_cert_path or DEFAULT_CA_CERT_PATH
    if trust_dir is None:
        trust_dir = os.environ.get("MSCHF_TRUST_DIR") or DEFAULT_TRUST_DIR

    pems = []
    if os.path.isfile(candidate_file):
        try:
            with open(candidate_file, "rb") as f:
                data = f.read()
            # Validate parse before including.
            x509.load_pem_x509_certificate(data, default_backend())
            pems.append(data)
        except Exception:
            print(f"Warning: skipping non-certificate trust file: {candidate_file}")

    if os.path.isdir(trust_dir):
        names = sorted(
            n for n in os.listdir(trust_dir)
            if n.lower().endswith((".crt", ".pem"))
        )
        for name in names:
            path = os.path.join(trust_dir, name)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as f:
                    data = f.read()
                x509.load_pem_x509_certificate(data, default_backend())
                pems.append(data)
            except Exception:
                print(f"Warning: skipping non-certificate trust file: {path}")

    # De-duplicate by SHA-256 of the certificate's DER encoding.
    seen = set()
    unique = []
    for pem in pems:
        try:
            cert = x509.load_pem_x509_certificate(pem, default_backend())
            der_hash = hashlib.sha256(
                cert.public_bytes(encoding=serialization.Encoding.DER)
            ).hexdigest()
        except Exception:
            # Should not happen (parsed above); skip defensively.
            continue
        if der_hash in seen:
            continue
        seen.add(der_hash)
        unique.append(pem)
    return unique


def is_cert_trusted(cert_pem, anchors):
    """True iff *cert_pem* chains to any anchor in *anchors*.

    Empty *anchors* always yields False (fail closed). *cert_pem* may be str
    or bytes.
    """
    if not anchors:
        return False
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("utf-8")
    for anchor in anchors:
        if is_cert_signed_by_ca(cert_pem, anchor):
            return True
    return False
