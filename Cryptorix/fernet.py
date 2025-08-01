from cryptography.fernet import Fernet, InvalidToken

from .exceptions import (
    EncryptionError,
    DecryptionError
)

__all__ = ["encrypt", "decrypt", "generate_key"]


def generate_key() -> bytes:
    """
    Generates a new Fernet-compatible key (base64-encoded 32-byte key).

    Returns:
        bytes: A Fernet key.
    """
    return Fernet.generate_key()


def encrypt(data: str, key: bytes) -> str:
    """
    Encrypts a string using Fernet (AES-CBC + HMAC).

    Args:
        data (str): Plaintext string.
        key (bytes): Fernet key.

    Returns:
        str: Encrypted string (base64-encoded).

    Raises:
        TypeError: If inputs are not of correct type.
        EncryptionError: If encryption fails.
    """
    if not isinstance(data, str):
        raise TypeError("Data must be a string.")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes.")

    try:
        fernet = Fernet(key)
        return fernet.encrypt(data.encode()).decode()
    except Exception as e:
        raise EncryptionError(f"Fernet encryption failed: {e}") from e


def decrypt(encrypted_data: str, key: bytes) -> str:
    """
    Decrypts a Fernet-encrypted base64 string.

    Args:
        encrypted_data (str): Base64-encoded ciphertext.
        key (bytes): Fernet key.

    Returns:
        str: Decrypted plaintext string.

    Raises:
        TypeError: If inputs are not of correct type.
        DecryptionError: If decryption fails or data is invalid.
    """
    if not isinstance(encrypted_data, str):
        raise TypeError("Encrypted data must be a string.")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes.")

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
        if name not in {"Fernet", "InvalidToken"}
    )
