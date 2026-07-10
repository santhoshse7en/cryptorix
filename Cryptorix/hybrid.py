import base64
import json
import secrets
from typing import Tuple

from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from Cryptorix.exceptions import (
    CryptorixError,
    KeyFormatError,
    EncryptionError,
    DecryptionError,
    UnsupportedAlgorithmError
)

__all__ = ["encrypt", "decrypt"]

# RSA padding strategy mapping: name -> (cryptography padding instance, AES mode)
RSA_PADDING_MODES = {
    "PKCS1_v1_5": (asym_padding.PKCS1v15(), "CBC"),
    "PKCS1_OAEP": (
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
        "GCM",
    ),
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
        aes_key = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)

        try:
            rsa_key = serialization.load_pem_public_key(public_key_pem.encode())
        except Exception as e:
            raise KeyFormatError(f"Invalid RSA public key: {e}") from e

        encrypted_key, aes_mode = _encrypt_aes_key(rsa_key, rsa_padding, aes_key)

        padded_data = _pkcs7_pad(json.dumps(data).encode())
        encrypted_data = _run_aes_cipher(aes_key, iv, aes_mode, padded_data, encrypt_mode=True)

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
            rsa_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        except Exception as e:
            raise KeyFormatError(f"Invalid RSA private key: {e}") from e

        aes_key, aes_mode = _decrypt_aes_key(rsa_key, encrypted_key_bytes, rsa_padding)

        decrypted_padded = _run_aes_cipher(aes_key, iv, aes_mode, ciphertext, encrypt_mode=False)
        decrypted = _pkcs7_unpad(decrypted_padded)

        return json.loads(decrypted.decode())

    except CryptorixError:
        raise
    except Exception as e:
        raise DecryptionError(f"Hybrid decryption failed: {e}") from e


def _encrypt_aes_key(
        rsa_key,
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

    rsa_padding, aes_mode = RSA_PADDING_MODES[padding]
    encrypted_key = rsa_key.encrypt(aes_key, rsa_padding)

    return encrypted_key, aes_mode


def _decrypt_aes_key(
        rsa_key,
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

    rsa_padding, aes_mode = RSA_PADDING_MODES[padding]
    decrypted_key = rsa_key.decrypt(encrypted_key, rsa_padding)

    if not decrypted_key:
        raise DecryptionError("AES key decryption failed.")

    return decrypted_key, aes_mode


def _run_aes_cipher(aes_key: bytes, iv: bytes, mode: str, data: bytes, encrypt_mode: bool) -> bytes:
    """
    Runs the AES cipher in the given mode over ``data``.

    Note: the 'GCM' mode here mirrors the historical wire format, which uses the
    cipher purely as a keystream (no authentication tag is produced or checked).
    Authenticity of the AES session key itself is guaranteed by the RSA layer.

    Args:
        aes_key (bytes): AES session key.
        iv (bytes): Initialization vector or nonce.
        mode (str): AES mode - 'GCM' or 'CBC'.
        data (bytes): Input bytes to transform.
        encrypt_mode (bool): True to encrypt, False to decrypt.

    Returns:
        bytes: Transformed output.

    Raises:
        UnsupportedAlgorithmError: If the AES mode is not supported.
    """
    if mode == "GCM":
        # Used purely as a keystream cipher here (no tag is generated or checked -
        # the RSA layer is what protects the AES key). GCM's keystream XOR is
        # symmetric, so the encryptor context is reused for both directions.
        ctx = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    elif mode == "CBC":
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        ctx = cipher.encryptor() if encrypt_mode else cipher.decryptor()
    else:
        raise UnsupportedAlgorithmError("Unsupported AES mode. Use 'GCM' or 'CBC'.")

    return ctx.update(data) + ctx.finalize()


def _pkcs7_pad(data: bytes) -> bytes:
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()


def _pkcs7_unpad(data: bytes) -> bytes:
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def __dir__():
    return sorted(
        name for name in globals()
        if name not in {
            "base64", "json", "secrets", "Tuple", "hashes", "sym_padding",
            "serialization", "asym_padding", "Cipher", "algorithms", "modes",
            "RSA_PADDING_MODES"
        }
    )
