import base64
import json
from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from Cryptorix.exceptions import (
    CryptorixError,
    KeyFormatError,
    EncryptionError,
    DecryptionError,
    UnsupportedAlgorithmError
)

__all__ = ["encrypt", "decrypt"]

# RSA padding strategy mapping
RSA_PADDING_MODES = {
    "PKCS1_v1_5": PKCS1_v1_5,
    "PKCS1_OAEP": PKCS1_OAEP,
}


def encrypt(
        data: dict,
        public_key_pem: str,
        rsa_padding: str = "PKCS1_OAEP",
) -> dict:
    """
    Encrypts data using RSA + AES hybrid encryption.

    Args:
        data (dict): The data to encrypt.
        public_key_pem (str): RSA public key in PEM format.
        rsa_padding (str): Padding mode: 'PKCS1_OAEP' (default) or 'PKCS1_v1_5'.

    Returns:
        dict: Base64-encoded encrypted AES key and encrypted payload.

    Raises:
        KeyFormatError: If the public key is invalid.
        EncryptionError: If encryption fails.
        UnsupportedAlgorithmError: If the padding is unsupported.
    """
    try:
        aes_key = get_random_bytes(16)
        iv = get_random_bytes(16)

        try:
            rsa_key = RSA.import_key(public_key_pem)
        except Exception as e:
            raise KeyFormatError(f"Invalid RSA public key: {e}") from e

        encrypted_key, aes_mode = _encrypt_aes_key(rsa_key, rsa_padding, aes_key)

        cipher = _init_aes_cipher(aes_key, iv, aes_mode)
        padded_data = pad(json.dumps(data).encode(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

        return {
            "encrypted_data": base64.b64encode(iv + encrypted_data).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
        }
    except CryptorixError:
        raise
    except Exception as e:
        raise EncryptionError(f"Hybrid encryption failed: {e}") from e


def decrypt(
        encrypted_data: str,
        encrypted_key: str,
        private_key_pem: str,
        rsa_padding: str = "PKCS1_OAEP",
) -> dict:
    """
    Decrypts data using RSA + AES hybrid decryption.

    Args:
        encrypted_data (str): Base64-encoded encrypted payload.
        encrypted_key (str): Base64-encoded encrypted AES key.
        private_key_pem (str): RSA private key in PEM format.
        rsa_padding (str): Padding mode: 'PKCS1_OAEP' (default) or 'PKCS1_v1_5'.

    Returns:
        dict: Original decrypted payload.

    Raises:
        KeyFormatError: If the private key is invalid.
        DecryptionError: If decryption fails.
        UnsupportedAlgorithmError: If the padding is unsupported.
    """
    try:
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        encrypted_key_bytes = base64.b64decode(encrypted_key)

        iv, ciphertext = encrypted_data_bytes[:16], encrypted_data_bytes[16:]

        try:
            rsa_key = RSA.import_key(private_key_pem)
        except Exception as e:
            raise KeyFormatError(f"Invalid RSA private key: {e}") from e

        aes_key, aes_mode = _decrypt_aes_key(rsa_key, encrypted_key_bytes, rsa_padding)

        cipher = _init_aes_cipher(aes_key, iv, aes_mode)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return json.loads(decrypted.decode())

    except CryptorixError:
        raise
    except Exception as e:
        raise DecryptionError(f"Hybrid decryption failed: {e}") from e


def _encrypt_aes_key(
        rsa_key: RSA.RsaKey,
        padding: str,
        aes_key: bytes,
) -> Tuple[bytes, str]:
    """
    Encrypts AES key using RSA with the given padding.

    Returns:
        Tuple[bytes, str]: Encrypted AES key, AES mode.

    Raises:
        UnsupportedAlgorithmError: If the padding is not supported.
    """
    if padding not in RSA_PADDING_MODES:
        raise UnsupportedAlgorithmError(
            "Unsupported RSA padding. Use 'PKCS1_v1_5' or 'PKCS1_OAEP'.")

    cipher = RSA_PADDING_MODES[padding].new(rsa_key)
    encrypted_key = cipher.encrypt(aes_key)

    return encrypted_key, "CBC" if padding == "PKCS1_v1_5" else "GCM"


def _decrypt_aes_key(
        rsa_key: RSA.RsaKey,
        encrypted_key: bytes,
        padding: str,
) -> Tuple[bytes, str]:
    """
    Decrypts AES key using RSA with the given padding.

    Returns:
        Tuple[bytes, str]: Decrypted AES key, AES mode.

    Raises:
        UnsupportedAlgorithmError: If the padding is not supported.
        DecryptionError: If the AES key cannot be decrypted.
    """
    if padding not in RSA_PADDING_MODES:
        raise UnsupportedAlgorithmError(
            "Unsupported RSA padding. Use 'PKCS1_v1_5' or 'PKCS1_OAEP'.")

    cipher = RSA_PADDING_MODES[padding].new(rsa_key)

    decrypted_key = (
        cipher.decrypt(encrypted_key, None)
        if padding == "PKCS1_v1_5"
        else cipher.decrypt(encrypted_key)
    )

    if not decrypted_key:
        raise DecryptionError("AES key decryption failed.")

    return decrypted_key, "CBC" if padding == "PKCS1_v1_5" else "GCM"


def _init_aes_cipher(aes_key: bytes, iv: bytes, mode: str) -> AES:
    """
    Initializes AES cipher.

    Args:
        aes_key (bytes): AES session key.
        iv (bytes): Initialization vector or nonce.
        mode (str): AES mode - 'GCM' or 'CBC'.

    Returns:
        AES cipher object.

    Raises:
        UnsupportedAlgorithmError: If the AES mode is not supported.
    """
    if mode == "GCM":
        return AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    elif mode == "CBC":
        return AES.new(aes_key, AES.MODE_CBC, iv)  # NOSONAR
    else:
        raise UnsupportedAlgorithmError("Unsupported AES mode. Use 'GCM' or 'CBC'.")


def __dir__():
    return sorted(
        name for name in globals()
        if name not in {
            "base64", "json", "Tuple", "AES", "PKCS1_OAEP", "PKCS1_v1_5", "RSA",
            "get_random_bytes", "pad", "unpad", "RSA_PADDING_MODES"
        }
    )
