import json

from cryptography.fernet import Fernet, InvalidToken

from .exceptions import (
    EncryptionError,
    DecryptionError
)

__all__ = ["encrypt", "decrypt", "generate_key"]


def generate_key() -> str:
    """
    Generates a new Fernet-compatible key (base64-encoded 32-byte key).

    Returns:
        str: A Fernet key.
    """
    return Fernet.generate_key().decode()


def encrypt(data: dict | str, key: str) -> str:
    """
    Encrypts a string using Fernet (AES-CBC + HMAC).

    Args:
        data (str): Plaintext string.
        key (str): Fernet key.

    Returns:
        str: Encrypted string (base64-encoded).

    Raises:
        TypeError: If inputs are not of correct type.
        EncryptionError: If encryption fails.
    """
    if not isinstance(data, (dict, str)):
        raise TypeError("Data must be a string.")
    if not isinstance(key, str):
        raise TypeError("Key must be str.")

    try:
        fernet = Fernet(key)

        if isinstance(data, dict):
            data = json.dumps(data)

        return fernet.encrypt(data.encode()).decode()
    except Exception as e:
        raise EncryptionError(f"Fernet encryption failed: {e}") from e


def decrypt(encrypted_data: str, key: str) -> str:
    """
    Decrypts a Fernet-encrypted base64 string.

    Args:
        encrypted_data (str): Base64-encoded ciphertext.
        key (str): Fernet key.

    Returns:
        str: Decrypted plaintext string.

    Raises:
        TypeError: If inputs are not of correct type.
        DecryptionError: If decryption fails or data is invalid.
    """
    if not isinstance(encrypted_data, str):
        raise TypeError("Encrypted data must be a string.")
    if not isinstance(key, str):
        raise TypeError("Key must be str.")

    try:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data.encode()).decode()
    except InvalidToken:
        raise DecryptionError("Fernet decryption failed: Invalid token.")
    except Exception as e:
        raise DecryptionError(f"Fernet decryption failed: {e}") from e


def __dir__():
    return sorted(
        name for name in globals()
        if name not in {"json", "Fernet", "InvalidToken"}
    )
