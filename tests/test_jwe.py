import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from Cryptorix import jwe


@pytest.fixture(scope="module")
def keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return public_pem, private_pem


def test_roundtrip(keypair):
    public_pem, private_pem = keypair
    payload = {"scopes": ["read"]}
    token = jwe.encrypt(payload, public_key_pem=public_pem)
    assert jwe.decrypt(token, private_key_pem=private_pem) == payload
