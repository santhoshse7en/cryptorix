import base64
import binascii
import json

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from Cryptorix.exceptions import EncryptionError


def encrypt(api_response: dict, aes_key: str) -> str:
    """
    Encrypts a plaintext dictionary using AES-GCM.

    Args:
        api_response (dict): The plaintext dictionary to encrypt.
        aes_key (str): The AES key as a hex string.

    Returns:
        str: The base64-encoded encrypted value.

    Raises:
        EncryptionError: If the encryption process fails.
    """
    try:
        iv = get_random_bytes(12)  # 12-byte IV for AES-GCM
        plain_bytes = json.dumps(api_response).encode("utf-8")

        cipher = AES.new(_decode_aes_key(aes_key), AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plain_bytes)

        # Concatenate iv, ciphertext, and tag, then base64 encode
        encrypted_data = base64.b64encode(iv + ciphertext + tag).decode("utf-8")
        return encrypted_data
    except Exception as error:
        raise EncryptionError(
            error=f"Encryption failed: {str(error)}",
            error_code="ENCRYPTION_ERROR",
            function_name="encrypt",
            context={"aes_key": "***MASKED***"}
        ) from error


def decrypt(encrypted_data: str, aes_key: str) -> dict:
    """
    Decrypts an AES-GCM encrypted base64-encoded string.

    Args:
        encrypted_data (str): The base64-encoded encrypted string.
        aes_key (str): The AES key as a hex string.

    Returns:
        dict: The decrypted plaintext dictionary.

    Raises:
        EncryptionError: If the decryption process fails.
    """
    try:
        encrypted_data_bytes = base64.b64decode(encrypted_data, validate=True)

        # Extract IV, ciphertext, and tag from the encrypted data
        iv, ciphertext, tag = (
            encrypted_data_bytes[:12],
            encrypted_data_bytes[12:-16],
            encrypted_data_bytes[-16:]
        )

        cipher = AES.new(_decode_aes_key(aes_key), AES.MODE_GCM, nonce=iv)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        return json.loads(decrypted_data.decode("utf-8"))
    except Exception as error:
        raise EncryptionError(
            error=f"Decryption failed: {str(error)}",
            error_code="DECRYPTION_ERROR",
            function_name="decrypt",
            context={"aes_key": "***MASKED***", "encrypted_data": encrypted_data[:30] + "..."}
        ) from error


def _decode_aes_key(aes_key: str) -> bytes:
    """
    Decodes the AES key from a hex string to raw bytes.

    Args:
        aes_key (str): The AES key as a hex string.

    Returns:
        bytes: The decoded AES key (32 bytes).

    Raises:
        ValueError: If the key is invalid.
    """
    if not isinstance(aes_key, str):
        raise ValueError("AES key must be a string.")

    try:
        decoded_key = binascii.unhexlify(aes_key)
        if len(decoded_key) != 32:
            raise ValueError("Invalid AES key length. Expected 32 bytes.")
        return decoded_key
    except binascii.Error as error:
        raise ValueError(f"Invalid AES key: {error}")
