"""Sample for cryptobom regression testing.

Mixes vulnerable, weak, misused, strong, and unanalyzable cryptographic usage
across pyca/cryptography and pycryptodome.
"""

import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def vulnerable(key):
    # Quantum-vulnerable asymmetric crypto.
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    eck = ec.generate_private_key(ec.SECP256R1())
    rkey = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(rkey)


def weak_and_misused(key):
    # Weak hashes/ciphers and a classic ECB misuse.
    h = hashlib.md5()
    h2 = hashlib.new("sha1")
    legacy = hashes.SHA1()
    des = DES.new(key, DES.MODE_ECB)
    aes_ecb = AES.new(key, AES.MODE_ECB)
    tdes = algorithms.TripleDES(key)


def strong_or_inventory(key, iv):
    # Good usage — must NOT be flagged as a problem.
    digest = hashlib.sha256()
    good = hashes.SHA256()
    aead = Cipher(algorithms.AES(key), modes.GCM(iv))


def unanalyzable(alg):
    # Non-literal or unqualified — must be ignored (no dataflow, no guessing).
    h = hashlib.new(alg)
    md5()
