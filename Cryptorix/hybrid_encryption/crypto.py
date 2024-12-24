import base64
import json
from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from Cryptorix.hybrid_encryption.exceptions import HybridEncryptionError
from Cryptorix.secrets.manager import retrieve_decrypted_secret_key, retrieve_secret_key


class HybridEncryptionService:
    """
    Service class responsible for encrypting and decrypting data using a hybrid encryption approach
    (AES-GCM for payloads and RSA for encrypting the AES session key).
    """

    # RSA padding types
    RSA_MODES = {
        "PKCS1_v1_5": PKCS1_v1_5,
        "PKCS1_OAEP": PKCS1_OAEP,
    }

    def encrypt(
            self,
            api_response: dict,
            secret_name: str,
            secret_key: str,
            kms_id: str = None,
            rsa_padding: str = "PKCS1_OAEP",
    ) -> dict:
        """
        Encrypts data using a hybrid encryption scheme.

        Args:
            api_response (dict): Plain Data to encrypt.
            secret_name (str): RSA secret name.
            secret_key (str): RSA key secret identifier.
            kms_id (str, optional): KMS unique identifier for decrypting the RSA key, if applicable.
            rsa_padding (str, optional): RSA padding method ('OAEP' or 'PKCS1_v1_5').

        Returns:
            dict: Contains Encrypted Data and Encrypted AES Session Key.
        """
        try:
            # Generate AES session key and IV
            aes_key = get_random_bytes(16)
            iv = get_random_bytes(16)

            # Load RSA key securely
            rsa_key = self._load_rsa_key(secret_name, secret_key, kms_id)

            # Encrypt AES session key with RSA
            encrypted_aes_key, aes_mode = self._encrypt_aes_key(
                rsa_key, rsa_padding, aes_key
            )

            # AES encrypt payload
            cipher_aes = self._initialize_aes_cipher(aes_key, iv, aes_mode)
            plaintext_bytes = pad(json.dumps(api_response).encode(), AES.block_size)
            ciphertext = cipher_aes.encrypt(plaintext_bytes)

            # Return response
            return {
                "encrypted_data": base64.b64encode(iv + ciphertext).decode("utf-8"),
                "encrypted_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
            }

        except Exception as error:
            raise HybridEncryptionError(
                error=str(error),
                error_code="ENCRYPTION_FAILED",
                function_name="encrypt",
                context={"secret_name": secret_name, "kms_id": kms_id}
            ) from error

    def decrypt(
            self,
            encrypted_data: str,
            encrypted_key: str,
            secret_name: str,
            secret_key: str,
            kms_id: str = None,
            rsa_padding: str = "PKCS1_OAEP"
    ) -> dict:
        """
        Decrypts data using a hybrid encryption mechanism.

        Args:
            encrypted_data (str): Base64-encoded encrypted payload.
            encrypted_key (str): Base64-encoded encrypted AES key.
            secret_name (str): RSA secret name.
            secret_key (str): RSA key secret identifier.
            kms_id (str, optional): KMS unique identifier for decrypting the RSA key, if applicable.
            rsa_padding (str, optional): RSA padding method.

        Returns:
            dict: Decrypted payload.
        """
        try:
            # Decode Base64 inputs
            encrypted_data_bytes = base64.b64decode(encrypted_data)
            encrypted_key_bytes = base64.b64decode(encrypted_key)

            # Extract IV and ciphertext
            iv, ciphertext = encrypted_data_bytes[:16], encrypted_data_bytes[16:]

            # Load RSA key securely
            rsa_key = self._load_rsa_key(secret_name, secret_key, kms_id)

            # Decrypt AES session key
            aes_key, aes_mode = self._decrypt_aes_key(
                rsa_key, encrypted_key_bytes, rsa_padding
            )

            # Initialize AES cipher
            cipher_aes = self._initialize_aes_cipher(aes_key, iv, aes_mode)
            plaintext_bytes = cipher_aes.decrypt(ciphertext)

            # Remove padding and Decode the result
            plaintext_bytes = unpad(plaintext_bytes, AES.block_size)
            return json.loads(plaintext_bytes.decode("utf-8"))

        except Exception as error:
            raise HybridEncryptionError(
                error=str(error),
                error_code="DECRYPTION_FAILED",
                function_name="decrypt",
                context={
                    "secret_name": secret_name,
                    "kms_id": kms_id,
                    "encrypted_key": encrypted_key[:30] + "...",  # Mask long values for logs
                    "encrypted_data": encrypted_data[:30] + "..."  # Mask long values for logs
                }
            ) from error

    @staticmethod
    def _load_rsa_key(secret_name: str, secret_key: str, kms_id: str) -> RSA.RsaKey:
        """
        Retrieves and validates the RSA key from a secrets manager.

        Args:
            secret_name (str): RSA secret name.
            secret_key (str): RSA key identifier.
            kms_id (str): KMS ID.

        Returns:
            RSA.RsaKey: Validated RSA key.
        """
        try:
            if kms_id:
                key_pem = retrieve_decrypted_secret_key(secret_name, secret_key, kms_id)
            else:
                key_pem = retrieve_secret_key(secret_name, secret_key)
            return RSA.import_key(key_pem)
        except Exception as e:
            raise HybridEncryptionError(
                error="Invalid RSA key or failed fetch",
                error_code="RSA_LOAD_ERROR",
                context={"secret_name": secret_name, "kms_id": kms_id}
            ) from e

    def _encrypt_aes_key(
            self,
            rsa_key: RSA.RsaKey,
            rsa_padding: str,
            aes_key: bytes
    ) -> Tuple[bytes, str]:
        """
        Encrypts the AES session key using RSA with the selected padding scheme.

        Args:
            rsa_key (RSA.RsaKey): The RSA public key object.
            rsa_padding (str): The type of RSA padding to use ('PKCS1_v1_5' or 'PKCS1_OAEP').
            aes_key (bytes): AES session key to encrypt.

        Returns:
            Tuple[bytes, str]: Encrypted AES session key and encryption mode.
        """
        try:
            if rsa_padding not in self.RSA_MODES:
                raise ValueError("Unsupported RSA padding type. Use 'PKCS1_v1_5' or 'PKCS1_OAEP'.")

            # Dynamically load the RSA cipher mode
            cipher = self.RSA_MODES[rsa_padding].new(rsa_key)
            encrypted_aes_key = cipher.encrypt(aes_key)

            # Return the encrypted AES session key and the corresponding AES mode
            return encrypted_aes_key, "CBC" if rsa_padding == "PKCS1_v1_5" else "GCM"
        except Exception as e:
            raise HybridEncryptionError(
                error="Failed to encrypt AES key",
                error_code="RSA_AES_KEY_ENCRYPT_FAILED",
                context={"rsa_padding": rsa_padding}
            ) from e

    def _decrypt_aes_key(
            self,
            rsa_key: RSA.RsaKey,
            encrypted_aes_key: bytes,
            rsa_padding: str
    ) -> Tuple[bytes, str]:
        """
        Decrypts the AES session key using RSA with the selected padding scheme.

        Args:
            rsa_key (RSA.RsaKey): The RSA private key object.
            encrypted_aes_key (bytes): The encrypted AES session key.
            rsa_padding (str): The type of RSA padding to use ('PKCS1_v1_5' or 'PKCS1_OAEP').

        Returns:
            Tuple[bytes, str]: The decrypted AES session key and mode.
        """
        try:
            if rsa_padding not in self.RSA_MODES:
                raise ValueError("Unsupported RSA padding type. Use 'PKCS1_v1_5' or 'PKCS1_OAEP'.")

            # Dynamically load the RSA decryption mode
            cipher = self.RSA_MODES[rsa_padding].new(rsa_key)

            if rsa_padding == "PKCS1_v1_5":
                # Handle PKCS1_v1_5 mode with sentinel
                decrypted_aes_key = cipher.decrypt(encrypted_aes_key, None)
            else:  # For PKCS1_OAEP or others, decrypt normally
                decrypted_aes_key = cipher.decrypt(encrypted_aes_key)

            if decrypted_aes_key is None:
                raise HybridEncryptionError(
                    error="RSA decryption failed.",
                    error_code="RSA_AES_KEY_DECRYPT_FAILED",
                    context={"rsa_padding": rsa_padding}
                )

            # Return the decrypted AES key and its respective mode
            return decrypted_aes_key, "CBC" if rsa_padding == "PKCS1_v1_5" else "GCM"
        except Exception as e:
            raise HybridEncryptionError(
                error="Failed to decrypt AES session key",
                error_code="RSA_AES_KEY_DECRYPT_FAILED",
                context={"rsa_padding": rsa_padding}
            ) from e

    @staticmethod
    def _initialize_aes_cipher(aes_key: bytes, iv: bytes, aes_mode: str):
        """
        Initializes the AES cipher instance.

        Args:
            aes_key (bytes): AES key.
            iv (bytes): Initialization vector.
            aes_mode (str): Cipher mode ('CBC' or 'GCM').

        Returns:
            AES cipher object.
        """
        if aes_mode == "GCM":
            return AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        if aes_mode == "CBC":
            return AES.new(aes_key, AES.MODE_CBC, iv)  # NOSONAR
        raise ValueError("Unsupported AES mode. Use 'GCM' or 'CBC'.")
