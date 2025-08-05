import base64
import json
import secrets

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .exceptions import (
    CryptorixError,
    EncryptionError,
    DecryptionError,
    KeyFormatError
)

__all__ = ["encrypt", "decrypt", "generate_key"]


def generate_key() -> str:
    """Generates a 256-bit (32-byte) AES key in hex format."""
    return secrets.token_hex(32)


def encrypt(data: dict | str, hex_key: str) -> str:
    """
    Encrypts a dictionary or string using AES-GCM and returns base64-encoded ciphertext.

    Args:
        data (dict | str): Data to encrypt.
        hex_key (str): Hex-encoded AES key (128/192/256-bit).

    Returns:
        str: Encrypted base64-encoded string.

    Raises:
        TypeError: If input is not a dictionary or string.
        KeyFormatError: If AES key is invalid.
        EncryptionError: For general encryption failures.
    """
    if not isinstance(data, (dict, str)):
        raise TypeError("Input data must be a dictionary or string.")

    try:
        key = _decode_aes_key(hex_key)
        iv = get_random_bytes(12)

        if isinstance(data, dict):
            data = json.dumps(data)

        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))

        encrypted = iv + ciphertext + tag
        return base64.b64encode(encrypted).decode("utf-8")

    except ValueError as e:
        raise KeyFormatError(f"Invalid AES key: {e}") from e
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}") from e


def decrypt(encrypted_data: str, hex_key: str) -> dict:
    """
    Decrypts a base64-encoded AES-GCM encrypted string.

    Args:
        encrypted_data (str): Base64-encoded ciphertext.
        hex_key (str): Hex-encoded AES key.

    Returns:
        dict: Decrypted data.

    Raises:
        KeyFormatError: If the key format is invalid.
        DecryptionError: If decryption fails.
    """
    try:
        encrypted_bytes = base64.b64decode(encrypted_data, validate=True)
    except Exception as e:
        raise DecryptionError(f"Invalid base64 input: {e}") from e

    if len(encrypted_bytes) < 28:
        raise DecryptionError("Encrypted data is too short or corrupted.")

    try:
        iv = encrypted_bytes[:12]
        tag = encrypted_bytes[-16:]
        ciphertext = encrypted_bytes[12:-16]

        key = _decode_aes_key(hex_key)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)

        result = json.loads(decrypted_bytes.decode("utf-8"))

        if not isinstance(result, dict):
            raise DecryptionError("Decrypted content is not a dictionary.")

        return result

    except CryptorixError:
        raise
    except ValueError as e:
        raise KeyFormatError(f"Invalid AES key: {e}") from e
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e


def _decode_aes_key(hex_key: str) -> bytes:
    """
    Decodes and validates a hex-encoded AES key.

    Args:
        hex_key (str): Hex-encoded AES key.

    Returns:
        bytes: Decoded AES key.

    Raises:
        KeyFormatError: If the key is not valid or not the correct length.
    """
    try:
        key_bytes = bytes.fromhex(hex_key)
    except ValueError:
        raise KeyFormatError("AES key must be a valid hexadecimal string.")

    if len(key_bytes) not in (16, 24, 32):
        raise KeyFormatError(
            f"Invalid AES key length: {len(key_bytes) * 8} bits. "
            "Supported lengths are 128, 192, or 256 bits."
        )

    return key_bytes


def __dir__():
    return sorted(
        name for name in globals()
        if name not in {"base64", "json", "secrets", "AES", "get_random_bytes"}
    )
