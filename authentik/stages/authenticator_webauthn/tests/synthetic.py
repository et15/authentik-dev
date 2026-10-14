"""Helpers to build fully self-contained, valid WebAuthn "packed" registration responses.

Real attestation chain validation needs a real certificate chain and a real signature over
`authData || clientDataHash`. Instead of depending on any real-world manufacturer
certificate (fragile, expires, external), these helpers generate a throwaway root CA, issue
a leaf attestation certificate from it, and sign a credential-creation response with it.
"""

import datetime
import hashlib
import json
import os
from base64 import urlsafe_b64encode

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from webauthn.helpers.encode_cbor import encode_cbor

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40

_NOT_BEFORE = datetime.datetime(2020, 1, 1)
_NOT_AFTER = datetime.datetime(2050, 1, 1)


def b64url(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode()


def generate_test_root_ca() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Generate a fresh self-signed root CA. Returns its private key (to issue leaf
    certificates with) and its PEM certificate (to store as a trusted root)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "authentik Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def build_synthetic_packed_attestation(
    aaguid: bytes,
    challenge: bytes,
    root_key: ec.EllipticCurvePrivateKey,
    rp_id: str = "localhost",
    origin: str = "http://localhost:9000",
    flags: int = FLAG_UP | FLAG_AT,
) -> dict:
    """Build a valid "packed" full-attestation registration response whose leaf certificate
    is issued by `root_key`'s CA. `flags` allows setting BE/BS/UV bits."""
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "authentik Test CA")])
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "authentik Test Attestation")])
        )
        .issuer_name(issuer)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    credential_id = os.urandom(32)
    numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    cose_key = encode_cbor(
        {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )
    auth_data = (
        hashlib.sha256(rp_id.encode()).digest()
        + bytes([flags])
        + (0).to_bytes(4, "big")
        + aaguid
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + cose_key
    )

    client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": b64url(challenge),
            "origin": origin,
            "crossOrigin": False,
        }
    ).encode()
    signature = leaf_key.sign(
        auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
    )
    attestation_object = encode_cbor(
        {
            "fmt": "packed",
            "attStmt": {
                "alg": -7,
                "sig": signature,
                "x5c": [leaf_cert.public_bytes(serialization.Encoding.DER)],
            },
            "authData": auth_data,
        }
    )
    return {
        "id": b64url(credential_id),
        "rawId": b64url(credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64url(client_data),
            "attestationObject": b64url(attestation_object),
        },
    }
