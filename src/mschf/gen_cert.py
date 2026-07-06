# Copyright 2018 Simon Davy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import uuid

# RSA modulus size for all generated keys (CA and user identities). 1024 is
# considered broken; 2048 is the current floor for RSA signing keys.
KEY_SIZE = 2048

def generate_selfsigned_cert(hostname, public_ip=None, private_ip=None):

    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
    alt_names = x509.SubjectAlternativeName([
        # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
        x509.DNSName(hostname),
        # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios)
        # openssl wants DNSnames for ips...
        #x509.DNSName(public_ip),
        #x509.DNSName(private_ip),
        # ... whereas golang's crypto/tls is stricter, and needs IPAddresses 
        #x509.IPAddress(public_ip),
        #x509.IPAddress(private_ip),
    ])
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=None)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(uuid.uuid4().int)
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(alt_names, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem

def generate_user_cert(common_name, ca_cert_pem, ca_key_pem):
    # Load CA cert and key
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None, backend=default_backend())
    
    # Generate user's private key
    user_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    
    # Create user Subject name
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    
    # User cert has BasicConstraints(ca=False)
    basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
    now = datetime.utcnow()
    
    # Build user cert signed by CA key
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(ca_cert.subject) # Issuer is the CA
        .public_key(user_key.public_key())
        .serial_number(uuid.uuid4().int)
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(basic_constraints, critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    
    cert_pem = user_cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = user_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem

def is_cert_signed_by_ca(user_cert_pem, ca_cert_pem):
    from cryptography.hazmat.primitives.asymmetric import padding
    if isinstance(user_cert_pem, str):
        user_cert_pem = user_cert_pem.encode('utf-8')
    if isinstance(ca_cert_pem, str):
        ca_cert_pem = ca_cert_pem.encode('utf-8')
    try:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
        user_cert = x509.load_pem_x509_certificate(user_cert_pem, default_backend())
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm
        )
        return True
    except Exception:
        return False
