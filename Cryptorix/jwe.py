import json

from jwcrypto import jwk, jwe

from Cryptorix.exceptions import EncryptionError
from Cryptorix.secrets import retrieve_decrypted_secret_key, retrieve_secret_key

# Encryption and decryption algorithms
ALGORITHM_KEY_ENC = "RSA-OAEP-256"
ALGORITHM_CONTENT_ENC = "A256GCM"


def encrypt(api_response: dict, secret_name: str, secret_key: str, kms_id: str = None) -> str:
    """
    Encrypt a dictionary into a JWE token using a public RSA key.

    Args:
        api_response (str): The plaintext data to encrypt.
        secret_name (str): Identifier for the RSA key pair.
        secret_key (str): Identifier for the RSA key pair secret.
        kms_id (str, optional): KMS unique identifier for decrypting the RSA key, if applicable.

    Returns:
        str: Compact serialized JWE token as a string

    Raises:
        JWEError: If encryption fails due to any exception.
    """
    try:
        # Fetch the RSA public key in PEM format
        public_key_pem = _load_rsa_key(secret_name, secret_key, kms_id)
        public_key = jwk.JWK.from_pem(public_key_pem.encode("utf-8"))

        # Prepare the JWE object with the given payload and encryption details
        jwe_token = jwe.JWE(
            plaintext=json.dumps(api_response).encode("utf-8"),
            recipient=public_key,
            protected={"alg": ALGORITHM_KEY_ENC, "enc": ALGORITHM_CONTENT_ENC}
        )

        # Serialize the JWE object in compact format
        return jwe_token.serialize(compact=True)

    except Exception as error:
        # Log and raise a specific JWE error for failure
        raise EncryptionError(
            error=str(error),
            error_code="ENCRYPTION_FAILED",
            function_name="encrypt",
            context={"secret_name": secret_name, "kms_id": kms_id},
        ) from error


def decrypt(jwe_payload: str, secret_name: str, secret_key: str, kms_id: str = None) -> dict:
    """
    Decrypt a JWE token into a dictionary using a private RSA key.

    Args:
        jwe_payload (str): Compact serialized JWE token to decrypt.
        secret_name (str): Identifier for the RSA key pair.
        secret_key (str): Identifier for the RSA key pair secret.
        kms_id (str, optional): KMS unique identifier for decrypting the RSA key, if applicable.

    Returns:
        dict: Decrypted dictionary payload

    Raises:
        JWEError: If encryption fails due to any exception.
    """
    try:
        # Fetch the RSA private key in PEM format
        private_key_pem = _load_rsa_key(secret_name, secret_key, kms_id)
        private_key = jwk.JWK.from_pem(private_key_pem.encode("utf-8"))

        # Deserialize the JWE token and decrypt using the private key
        jwe_token = jwe.JWE()
        jwe_token.deserialize(jwe_payload, key=private_key)

        # Decode and parse the payload into a dictionary
        return json.loads(jwe_token.payload.decode("utf-8"))

    except Exception as error:
        # Log and raise a specific JWE error for failure
        raise EncryptionError(
            error=str(error),
            error_code="DECRYPTION_FAILED",
            function_name="decrypt",
            context={
                "secret_name": secret_name,
                "kms_id": kms_id,
                "jwe_payload": jwe_payload[:30] + "..."  # Mask long values for logs
            },
        ) from error


def _load_rsa_key(secret_name: str, secret_key: str, kms_id: str) -> str:
    """
    Retrieves and validates the RSA key from a secrets' manager.

    Args:
        secret_name (str): RSA secret name.
        secret_key (str): RSA key identifier.
        kms_id (str): KMS ID.

    Returns:
        str: RSA key.
    """
    try:
        if kms_id:
            return retrieve_decrypted_secret_key(secret_name, secret_key, kms_id)
        else:
            return retrieve_secret_key(secret_name, secret_key)
    except Exception as error:
        raise EncryptionError(
            error="Invalid RSA key or failed fetch",
            error_code="RSA_LOAD_ERROR",
            context={"secret_name": secret_name, "kms_id": kms_id}
        ) from error
