import base64
import json
import secrets
import string

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .exceptions import (
    CryptorixError,
    EncryptionError,
    DecryptionError,
    KeyFormatError
)

__all__ = ["encrypt", "decrypt", "generate_key_str", "generate_key_hex"]


def generate_key_str() -> str:
    """
    Generates a random AES key as a raw string of given length.
    (Each character = 1 byte when encoded with UTF-8)

    Default: 32 chars (256-bit).
    """
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(32))


def generate_key_hex() -> str:
    """
    Generates a 256-bit (32-byte) AES key in hex format.
    Returns a 64-character hex string.
    """
    return secrets.token_hex(32)


def encrypt(data: dict | str, aes_key: str) -> str:
    """
    Encrypts a dictionary or string using AES-GCM and returns base64-encoded ciphertext.

    Args:
        data (dict | str): Data to encrypt.
        aes_key (str): AES key (128/192/256-bit).

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
        key = _decode_aes_key(aes_key)
        iv = get_random_bytes(12)

        plaintext = json.dumps(data) if isinstance(data, dict) else data
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

        return base64.b64encode(iv + ciphertext + tag).decode("utf-8")

    except ValueError as e:
        raise KeyFormatError(f"Invalid AES key: {e}") from e
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}") from e


def decrypt(encrypted_data: str, aes_key: str) -> dict | str:
    """
    Decrypts a base64-encoded AES-GCM encrypted string.

    Args:
        encrypted_data (str): Base64-encoded ciphertext.
        aes_key (str): AES key.

    Returns:
        dict | str: Decrypted JSON object or plain string.

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

        key = _decode_aes_key(aes_key)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)

        try:
            result = json.loads(decrypted_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            result = decrypted_bytes.decode("utf-8")

        return result

    except CryptorixError:
        raise
    except ValueError as e:
        raise KeyFormatError(f"Invalid AES key: {e}") from e
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e

def _decode_aes_key(aes_key: str) -> bytes:
    """
    Decodes and validates an AES key that may be provided as:
      - Hex string (32, 48, or 64 hex chars → 16, 24, or 32 bytes)
      - Raw UTF-8 string (16, 24, or 32 chars → same length in bytes)

    Returns:
        bytes: Decoded AES key.

    Raises:
        KeyFormatError: If the key format is invalid or length is unsupported.
    """
    # Try hex
    try:
        key_bytes = bytes.fromhex(aes_key)
        if len(key_bytes) in (16, 24, 32):
            return key_bytes
    except ValueError:
        pass

    # Fallback: UTF-8
    key_bytes = aes_key.encode("utf-8")
    if len(key_bytes) in (16, 24, 32):
        return key_bytes

    raise KeyFormatError(
        f"Invalid AES key length: {len(key_bytes) * 8} bits. "
        "Supported lengths are 128, 192, or 256 bits."
    )


def __dir__():
    return sorted(
        name for name in globals()
        if name not in {"base64", "json", "string", "secrets", "AES", "get_random_bytes"}
    )
