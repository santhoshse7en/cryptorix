import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from Cryptorix import hybrid


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


@pytest.mark.parametrize("padding", ["PKCS1_OAEP", "PKCS1_v1_5"])
def test_roundtrip(keypair, padding):
    public_pem, private_pem = keypair
    payload = {"id": 1, "scopes": ["read", "write"]}

    bundle = hybrid.encrypt(payload, public_key_pem=public_pem, rsa_padding=padding)
    result = hybrid.decrypt(
        encrypted_data=bundle["encrypted_data"],
        encrypted_key=bundle["encrypted_key"],
        private_key_pem=private_pem,
        rsa_padding=padding,
    )
    assert result == payload
