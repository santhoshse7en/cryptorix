from __future__ import annotations

import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .exceptions import KeyDerivationError, KeyFormatError

__all__ = [
    "derive_key_argon2id",
    "derive_key_scrypt",
    "derive_key_hkdf",
    "generate_salt_hex",
]

_VALID_LENGTHS = (16, 24, 32)


def generate_salt_hex(length: int = 16) -> str:
    """
    Generates a random salt and returns it as a hex string.
    """
    return os.urandom(length).hex()


def derive_key_argon2id(
        password: str,
        salt_hex: str | None = None,
        *,
        length: int = 32,
        time_cost: int = 3,
        memory_cost: int = 64 * 1024,
        parallelism: int = 4,
) -> Tuple[str, str]:
    """
    Derives an AES-ready key from a password using Argon2id (OWASP's recommended
    password hashing default).

    Args:
        password (str): The password to derive a key from.
        salt_hex (str | None): Existing salt as hex; omit to generate a new random salt.
        length (int): Output key length in bytes - 16, 24, or 32 (AES key sizes).
        time_cost (int): Number of iterations.
        memory_cost (int): Memory usage in KiB.
        parallelism (int): Degree of parallelism (lanes).

    Returns:
        Tuple[str, str]: (key_hex, salt_hex). Persist salt_hex - it is required to
        re-derive the same key later (e.g. to decrypt data encrypted with it).

    Raises:
        KeyFormatError: If length is not a supported AES key size.
        KeyDerivationError: If derivation fails.
    """
    if length not in _VALID_LENGTHS:
        raise KeyFormatError(
            f"Invalid key length: {length} bytes. Supported lengths are 16, 24, or 32 bytes."
        )

    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)

    try:
        kdf = Argon2id(
            salt=salt,
            length=length,
            iterations=time_cost,
            lanes=parallelism,
            memory_cost=memory_cost,
        )
        key = kdf.derive(password.encode("utf-8"))
        return key.hex(), salt.hex()
    except Exception as e:
        raise KeyDerivationError(f"Argon2id key derivation failed: {e}") from e


def derive_key_scrypt(
        password: str,
        salt_hex: str | None = None,
        *,
        length: int = 32,
        cost_factor: int = 2 ** 14,
        block_size: int = 8,
        parallelism: int = 1,
) -> Tuple[str, str]:
    """
    Derives an AES-ready key from a password using scrypt.

    Args:
        password (str): The password to derive a key from.
        salt_hex (str | None): Existing salt as hex; omit to generate a new random salt.
        length (int): Output key length in bytes - 16, 24, or 32 (AES key sizes).
        cost_factor (int): CPU/memory cost parameter (must be a power of 2).
        block_size (int): Block size parameter.
        parallelism (int): Parallelization parameter.

    Returns:
        Tuple[str, str]: (key_hex, salt_hex). Persist salt_hex - it is required to
        re-derive the same key later.

    Raises:
        KeyFormatError: If length is not a supported AES key size.
        KeyDerivationError: If derivation fails.
    """
    if length not in _VALID_LENGTHS:
        raise KeyFormatError(
            f"Invalid key length: {length} bytes. Supported lengths are 16, 24, or 32 bytes."
        )

    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)

    try:
        kdf = Scrypt(salt=salt, length=length, n=cost_factor, r=block_size, p=parallelism)
        key = kdf.derive(password.encode("utf-8"))
        return key.hex(), salt.hex()
    except Exception as e:
        raise KeyDerivationError(f"Scrypt key derivation failed: {e}") from e


def derive_key_hkdf(
        input_key_material: bytes,
        *,
        length: int = 32,
        salt: bytes | None = None,
        info: bytes = b"",
) -> str:
    """
    Expands existing high-entropy key material (e.g. a shared secret or a
    KMS-decrypted key) into an AES-ready key using HKDF-SHA256.

    Unlike Argon2id/scrypt, HKDF is not a password hash - it assumes the input
    is already high-entropy and is meant for domain-separating/expanding keys,
    not for hashing low-entropy secrets like passwords.

    Args:
        input_key_material (bytes): High-entropy input keying material.
        length (int): Output key length in bytes - 16, 24, or 32 (AES key sizes).
        salt (bytes | None): Optional salt; HKDF works securely without one.
        info (bytes): Optional context/application-specific info for domain separation.

    Returns:
        str: Derived key as a hex string.

    Raises:
        KeyFormatError: If length is not a supported AES key size.
        KeyDerivationError: If derivation fails.
    """
    if length not in _VALID_LENGTHS:
        raise KeyFormatError(
            f"Invalid key length: {length} bytes. Supported lengths are 16, 24, or 32 bytes."
        )

    try:
        kdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
        return kdf.derive(input_key_material).hex()
    except Exception as e:
        raise KeyDerivationError(f"HKDF key derivation failed: {e}") from e


def __dir__():
    return sorted(
        name for name in globals()
        if name not in {
            "os", "Tuple", "hashes", "Argon2id", "HKDF", "Scrypt", "_VALID_LENGTHS"
        }
    )
