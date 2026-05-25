"""Sample for cryptobom regression testing.

Mixes vulnerable, weak, misused, strong, and unanalyzable cryptographic usage
across pyca/cryptography and pycryptodome.
"""

import hashlib
import hmac
import oqs
import random
import secrets
import ssl


def post_quantum():
    # Post-quantum algorithm (liboqs) — inventoried as quantum-safe.
    kem = oqs.KeyEncapsulation("Kyber768")
    sig = oqs.Signature("Dilithium3")


def tls_setup():
    # TLS protocol constants/enums: deprecated flagged, modern inventoried.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def vulnerable(key):
    # Quantum-vulnerable asymmetric crypto (key sizes / curves captured).
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    eck = ec.generate_private_key(ec.SECP256R1())
    rkey = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(rkey)
    # Classically weak parameters (also flagged on top of quantum-vulnerability).
    weak_curve = ec.generate_private_key(ec.SECP192R1())


def weak_and_misused(key):
    # Weak hashes/ciphers and a classic ECB misuse.
    h = hashlib.md5()
    h2 = hashlib.new("sha1")
    legacy = hashes.SHA1()
    des = DES.new(key, DES.MODE_ECB)
    aes_ecb = AES.new(key, AES.MODE_ECB)
    tdes = algorithms.TripleDES(key)


def hardcoded():
    # Hardcoded key and static IV — literal material in source.
    enc = AES.new(b"0123456789abcdef", AES.MODE_CBC, iv=b"0000000000000000")
    sym = algorithms.AES(b"hardcoded-key-16")
    static = modes.CBC(b"0000000000000000")


def weak_random_key():
    # Key material from the non-cryptographic random module — flagged via sink taint.
    weak = random.randbytes(16)
    enc = AES.new(weak, AES.MODE_CBC)
    # secrets is correct — must NOT be flagged.
    good = secrets.token_bytes(16)
    ok = AES.new(good, AES.MODE_CBC)


def timing_compare(key, msg, provided):
    tag = hmac.new(key, msg).digest()
    # Non-constant-time comparison of a MAC — flagged.
    if tag == provided:
        return False
    # Constant-time comparison — must NOT be flagged.
    if hmac.compare_digest(tag, provided):
        return True
    # Non-crypto comparison — must NOT be flagged.
    return msg == provided


def strong_or_inventory(key, iv):
    # Good usage — must NOT be flagged as a problem.
    digest = hashlib.sha256()
    good = hashes.SHA256()
    aead = Cipher(algorithms.AES(key), modes.GCM(iv))


def unanalyzable(alg):
    # Non-literal or unqualified — must be ignored (no dataflow, no guessing).
    h = hashlib.new(alg)
    md5()
