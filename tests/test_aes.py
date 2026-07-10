import pytest

from Cryptorix import aes
from Cryptorix.exceptions import KeyFormatError, DecryptionError


def test_generate_key_hex_length():
    assert len(aes.generate_key_hex()) == 64


def test_generate_key_str_length():
    assert len(aes.generate_key_str()) == 32


@pytest.mark.parametrize("key_factory", [aes.generate_key_hex, aes.generate_key_str])
def test_roundtrip_dict(key_factory):
    key = key_factory()
    payload = {"user": 42, "role": "admin"}
    token = aes.encrypt(payload, aes_key=key)
    assert aes.decrypt(token, aes_key=key) == payload


def test_roundtrip_str():
    key = aes.generate_key_hex()
    token = aes.encrypt("plain text", aes_key=key)
    assert aes.decrypt(token, aes_key=key) == "plain text"


def test_invalid_key_length():
    with pytest.raises(KeyFormatError):
        aes.encrypt("data", aes_key="short")


def test_wrong_key_fails_decrypt():
    token = aes.encrypt("secret", aes_key=aes.generate_key_hex())
    with pytest.raises(DecryptionError):
        aes.decrypt(token, aes_key=aes.generate_key_hex())
