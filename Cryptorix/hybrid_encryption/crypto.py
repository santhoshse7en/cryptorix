import base64
import json

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from Cryptorix.hybrid_encryption.exceptions import HybridEncryptionError
from Cryptorix.secrets.manager import get_rsa_key


def encrypt(api_response: dict, secret_name: str, secret_key: str, kms_id: str) -> dict:
    """
    Encrypts data using a hybrid encryption scheme (AES-GCM for data, RSA for an AES key).

    Args:
        api_response (dict): The plaintext data to encrypt.
        secret_name (str): Identifier for the RSA key pair.
        secret_key (str): Identifier for the RSA key pair secret.
        kms_id (str): Unique identifier for the Key Management System.

    Returns:
        dict: Contains Base64-encoded AES-encrypted data and RSA-encrypted AES key.

    Raises:
        HybridEncryptionError: If encryption fails due to any exception.
    """
    try:
        # Generate AES session key and initialization vector (IV)
        aes_key = get_random_bytes(16)  # AES-128 session key
        iv = get_random_bytes(16)  # AES-GCM requires 16-byte IV

        # Encrypt data using AES in GCM mode with padding
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, iv)
        ciphertext = cipher_aes.encrypt(pad(json.dumps(api_response).encode(), AES.block_size))

        # Fetch an RSA public key for encrypting the AES session key
        public_key = get_rsa_key(secret_name, secret_key, kms_id)
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        enc_aes_key = cipher_rsa.encrypt(aes_key)

        # Return Base64-encoded encrypted data and key
        return {
            "encryptedData": base64.b64encode(iv + ciphertext).decode("utf-8"),
            "encryptedKey": base64.b64encode(enc_aes_key).decode("utf-8")
        }
    except Exception as error:
        raise HybridEncryptionError(
            error=str(error),
            error_code="ENCRYPTION_FAILED",
            function_name="encrypt",
            context={
                "secret_name": secret_name, "kms_id": kms_id
            }
        ) from error


def decrypt(
        encrypted_data: str,
        encrypted_key: str,
        secret_name: str,
        secret_key: str,
        kms_id: str
) -> dict:
    """
    Decrypts encrypted data with the hybrid encryption scheme (AES-GCM for data, RSA for an AES
    key).

    Args:
        encrypted_data (str): Base64-encoded AES-encrypted data.
        encrypted_key (str): Base64-encoded RSA-encrypted AES key.
        secret_name (str): Identifier for the RSA key pair.
        secret_key (str): Identifier for the RSA key pair secret.
        kms_id (str): Unique identifier for the Key Management System.

    Returns:
        dict: The original plaintext data as a dictionary.

    Raises:
        HybridEncryptionError: If decryption fails due to any exception.
    """
    try:
        # Decode Base64 inputs
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        encrypted_key_bytes = base64.b64decode(encrypted_key)

        # Extract IV (first 16 bytes) and ciphertext (remaining bytes)
        iv = encrypted_data_bytes[:16]
        ciphertext = encrypted_data_bytes[16:]

        # Fetch an RSA private key for decrypting the AES session key
        private_key = get_rsa_key(secret_name, secret_key, kms_id)
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        aes_key = cipher_rsa.decrypt(encrypted_key_bytes)

        # Decrypt data using AES in GCM mode and remove padding
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, iv)
        plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

        # Parse and return the plaintext as a JSON object
        return json.loads(plaintext.decode("utf-8"))
    except Exception as error:
        raise HybridEncryptionError(
            error=str(error),
            error_code="DECRYPTION_FAILED",
            function_name="decrypt",
            context={
                "secret_name": secret_name,
                "kms_id": kms_id,
                "encrypted_data_snippet": encrypted_data[:30] + "..."
            }
        ) from error
