import pytest

from Cryptorix import fpe
from Cryptorix.exceptions import KeyFormatError


@pytest.fixture
def key():
    return fpe.generate_key_hex()


def test_generate_key_hex_length(key):
    assert len(key) == 64


@pytest.mark.parametrize(
    "data,alphabet",
    [
        ("464024070979", fpe.ALPHABET_NUMERIC),
        ("HELLOWORLD", fpe.ALPHABET_ALPHA),
        ("ABC123XYZ987", fpe.ALPHABET_ALPHANUMERIC),
    ],
)
def test_roundtrip(key, data, alphabet):
    token = fpe.encrypt(data, key=key, alphabet=alphabet)
    assert len(token) == len(data)
    assert all(ch in alphabet for ch in token)
    assert fpe.decrypt(token, key=key, alphabet=alphabet) == data


def test_custom_alphabet_lowercase_and_digits(key):
    import string
    alphabet = string.ascii_lowercase + string.digits
    data = "a1b2c3d4"
    token = fpe.encrypt(data, key=key, alphabet=alphabet)
    assert fpe.decrypt(token, key=key, alphabet=alphabet) == data


def test_different_keys_produce_different_ciphertext():
    data = "464024070979"
    token1 = fpe.encrypt(data, key=fpe.generate_key_hex())
    token2 = fpe.encrypt(data, key=fpe.generate_key_hex())
    assert token1 != token2


def test_wrong_key_does_not_recover_plaintext():
    data = "464024070979"
    token = fpe.encrypt(data, key=fpe.generate_key_hex())
    result = fpe.decrypt(token, key=fpe.generate_key_hex())
    assert result != data
    assert len(result) == len(data)


def test_short_key_rejected():
    with pytest.raises(KeyFormatError):
        fpe.encrypt("464024070979", key="short")


def test_invalid_character_rejected(key):
    with pytest.raises(ValueError):
        fpe.encrypt("46402407097X", key=key, alphabet=fpe.ALPHABET_NUMERIC)


def test_too_short_input_rejected(key):
    with pytest.raises(ValueError):
        fpe.encrypt("5", key=key, alphabet=fpe.ALPHABET_NUMERIC)


def test_small_domain_warns(key):
    with pytest.warns(UserWarning):
        fpe.encrypt("12", key=key, alphabet=fpe.ALPHABET_NUMERIC)
