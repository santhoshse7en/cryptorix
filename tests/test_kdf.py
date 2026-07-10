import pytest

from Cryptorix import aes, kdf
from Cryptorix.exceptions import KeyFormatError


@pytest.mark.parametrize("derive", [kdf.derive_key_argon2id, kdf.derive_key_scrypt])
def test_same_password_and_salt_reproduce_key(derive):
    key1, salt = derive("correct horse battery staple")
    key2, _ = derive("correct horse battery staple", salt_hex=salt)
    assert key1 == key2


@pytest.mark.parametrize("derive", [kdf.derive_key_argon2id, kdf.derive_key_scrypt])
def test_different_salt_gives_different_key(derive):
    key1, salt1 = derive("same password")
    key2, salt2 = derive("same password")
    assert salt1 != salt2
    assert key1 != key2


@pytest.mark.parametrize("derive", [kdf.derive_key_argon2id, kdf.derive_key_scrypt])
def test_invalid_length_rejected(derive):
    with pytest.raises(KeyFormatError):
        derive("password", length=10)


def test_derived_key_works_with_aes():
    key_hex, salt_hex = kdf.derive_key_argon2id("hunter2")
    token = aes.encrypt({"ok": True}, aes_key=key_hex)

    rederived_key_hex, _ = kdf.derive_key_argon2id("hunter2", salt_hex=salt_hex)
    assert aes.decrypt(token, aes_key=rederived_key_hex) == {"ok": True}


def test_hkdf_expands_deterministically():
    secret = b"shared-secret-material-from-somewhere"
    key1 = kdf.derive_key_hkdf(secret, info=b"session-key")
    key2 = kdf.derive_key_hkdf(secret, info=b"session-key")
    key3 = kdf.derive_key_hkdf(secret, info=b"other-context")
    assert key1 == key2
    assert key1 != key3
    assert len(bytes.fromhex(key1)) == 32


def test_generate_salt_hex_length():
    assert len(bytes.fromhex(kdf.generate_salt_hex())) == 16
