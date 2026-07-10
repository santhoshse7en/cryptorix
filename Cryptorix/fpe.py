"""
Format Preserving Encryption (FPE): output has the same length and alphabet
as the input (e.g. a 12-digit card number encrypts to another 12-digit
number). Useful for tokenizing structured identifiers in place, without
changing column types/lengths downstream.

Unlike AES-GCM or Fernet, this scheme carries no authentication tag - by
construction, format-preserving ciphertext has no room to also carry a MAC.
Decrypting with the wrong key silently returns a different (wrong) but still
validly-formatted string rather than raising an error. Only use this for
data where that tradeoff is acceptable (tokenization/masking), and pair it
with an out-of-band integrity check if you need to detect tampering.
"""

import hashlib
import hmac
import itertools
import math
import secrets
import string
import warnings
from typing import Iterator, List

from .exceptions import DecryptionError, EncryptionError, KeyFormatError

__all__ = [
    "encrypt",
    "decrypt",
    "generate_key_hex",
    "ALPHABET_NUMERIC",
    "ALPHABET_ALPHA",
    "ALPHABET_ALPHANUMERIC",
]

# Preset alphabets - pass any custom string as `alphabet` for other charsets.
ALPHABET_NUMERIC = string.digits
ALPHABET_ALPHA = string.ascii_uppercase
ALPHABET_ALPHANUMERIC = string.ascii_uppercase + string.digits

_ROUNDS = 10
_MIN_DOMAIN_SIZE = 1_000_000  # NIST SP 800-38G's minimum recommended domain size


def generate_key_hex() -> str:
    """
    Generates a 256-bit (32-byte) FPE key in hex format.
    Returns a 64-character hex string.
    """
    return secrets.token_hex(32)


def encrypt(data: str, key: str, alphabet: str = ALPHABET_ALPHANUMERIC) -> str:
    """
    Encrypts a string into a ciphertext of the same length and alphabet
    (Format Preserving Encryption), e.g. tokenizing a 12-digit card number
    into another 12-digit number.

    This is a generic Feistel-network construction keyed with HMAC-SHA256,
    not a NIST-certified FF1/FF3-1 implementation. It is well suited to
    tokenization/masking use cases; for FPE required by a formal compliance
    scope (e.g. PCI DSS), use a certified FF1 implementation instead.

    Args:
        data (str): Plaintext, every character must be in `alphabet`.
        key (str): Secret key (hex string or raw UTF-8 string).
        alphabet (str): Character set `data` is drawn from. Defaults to
            uppercase letters + digits. Use `ALPHABET_NUMERIC`,
            `ALPHABET_ALPHA`, or a custom string for other charsets.

    Returns:
        str: Ciphertext - same length and alphabet as `data`.

    Raises:
        TypeError: If data or alphabet is not a string.
        ValueError: If data is empty, too short, or contains characters
            outside `alphabet`.
        KeyFormatError: If the key is invalid.
        EncryptionError: For general encryption failures.
    """
    indices = _pack(data, alphabet)
    key_bytes = _decode_key(key)

    try:
        radix = len(alphabet)
        _warn_if_domain_too_small(radix, len(data))
        encrypted = _feistel_encrypt(key_bytes, radix, indices)
        return _unpack(encrypted, alphabet)
    except (TypeError, ValueError, KeyFormatError):
        raise
    except Exception as e:
        raise EncryptionError(f"FPE encryption failed: {e}") from e


def decrypt(data: str, key: str, alphabet: str = ALPHABET_ALPHANUMERIC) -> str:
    """
    Decrypts a ciphertext produced by `encrypt` back into the original string.

    Args:
        data (str): Ciphertext, every character must be in `alphabet`.
        key (str): Secret key (hex string or raw UTF-8 string).
        alphabet (str): Same character set used for encryption.

    Returns:
        str: Decrypted plaintext - same length and alphabet as `data`.

    Raises:
        TypeError: If data or alphabet is not a string.
        ValueError: If data is empty, too short, or contains characters
            outside `alphabet`.
        KeyFormatError: If the key is invalid.
        DecryptionError: For general decryption failures.
    """
    indices = _pack(data, alphabet)
    key_bytes = _decode_key(key)

    try:
        radix = len(alphabet)
        decrypted = _feistel_decrypt(key_bytes, radix, indices)
        return _unpack(decrypted, alphabet)
    except (TypeError, ValueError, KeyFormatError):
        raise
    except Exception as e:
        raise DecryptionError(f"FPE decryption failed: {e}") from e


def _pack(data: str, alphabet: str) -> List[int]:
    if not isinstance(data, str) or not isinstance(alphabet, str):
        raise TypeError("data and alphabet must be strings.")

    if len(data) < 2:
        raise ValueError("Input must be at least 2 characters long.")

    if len(set(alphabet)) != len(alphabet):
        raise ValueError("alphabet must not contain duplicate characters.")

    index_of = {ch: i for i, ch in enumerate(alphabet)}
    try:
        return [index_of[ch] for ch in data]
    except KeyError as e:
        raise ValueError(f"Input contains a character outside the alphabet: {e}") from e


def _unpack(indices: List[int], alphabet: str) -> str:
    return "".join(alphabet[i] for i in indices)


def _decode_key(key: str) -> bytes:
    """
    Decodes an FPE key that may be provided as a hex string or a raw UTF-8
    string. Unlike AES, HMAC keys have no fixed required length - only a
    recommended minimum for adequate entropy.
    """
    if not isinstance(key, str) or not key:
        raise KeyFormatError("Key must be a non-empty string.")

    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        key_bytes = key.encode("utf-8")

    if len(key_bytes) < 16:
        raise KeyFormatError(
            f"Key is too short ({len(key_bytes)} bytes). Use at least 16 bytes "
            "of entropy, e.g. Cryptorix.fpe.generate_key_hex()."
        )
    return key_bytes


def _warn_if_domain_too_small(radix: int, length: int) -> None:
    if radix ** length < _MIN_DOMAIN_SIZE:
        warnings.warn(
            f"FPE domain size ({radix}^{length}) is below the NIST-recommended "
            f"minimum of {_MIN_DOMAIN_SIZE}; ciphertexts may be brute-forceable.",
            stacklevel=3,
        )


def _round_keystream(key: bytes, radix: int, round_index: int, half: List[int]) -> Iterator[int]:
    digest_size = hashlib.sha256().digest_size
    chars_per_hash = max(1, int(digest_size * math.log(256, radix)))
    seed = round_index.to_bytes(4, "big") + bytes(half)
    counter = 0
    while True:
        digest = hmac.new(key, seed + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        value = int.from_bytes(digest, "big")
        for _ in range(chars_per_hash):
            value, remainder = divmod(value, radix)
            yield remainder
        seed = digest
        counter += 1


def _split(values: List[int]):
    midpoint = len(values) // 2
    return values[:midpoint], values[midpoint:]


def _feistel_encrypt(key: bytes, radix: int, values: List[int]) -> List[int]:
    a, b = _split(values)
    for i in range(_ROUNDS):
        keystream = list(itertools.islice(_round_keystream(key, radix, i, b), len(a)))
        c = [(x + y) % radix for x, y in zip(a, keystream)]
        a, b = b, c
    return a + b


def _feistel_decrypt(key: bytes, radix: int, values: List[int]) -> List[int]:
    a, b = _split(values)
    for i in range(_ROUNDS - 1, -1, -1):
        b, c = a, b
        keystream = list(itertools.islice(_round_keystream(key, radix, i, b), len(c)))
        a = [(x - y) % radix for x, y in zip(c, keystream)]
    return a + b


def __dir__():
    return sorted(
        name for name in globals()
        if name not in {
            "hashlib", "hmac", "itertools", "math", "secrets", "string", "warnings",
            "Iterator", "List", "_ROUNDS", "_MIN_DOMAIN_SIZE"
        }
    )
