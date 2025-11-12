import json

from jwcrypto import jwk, jwe

__all__ = ["encrypt", "decrypt"]

from Cryptorix.exceptions import EncryptionError, DecryptionError, KeyFormatError

# Encryption algorithms
ALGORITHM_KEY_ENC = "RSA-OAEP-256"
ALGORITHM_CONTENT_ENC = "A256GCM"


def encrypt(data: dict, public_key_pem: str) -> str:
    """
    Encrypts a dictionary into a JWE compact token using an RSA public key.

    Args:
        data (dict): Payload to encrypt.
        public_key_pem (str): RSA public key in PEM format.

    Returns:
        str: Compact JWE token.

    Raises:
        KeyFormatError: If the public key is invalid.
        EncryptionError: If encryption fails.
    """
    if not isinstance(data, dict):
        raise TypeError("Input data must be a dictionary.")

    try:
        public_jwk = jwk.JWK.from_pem(public_key_pem.encode("utf-8"))
    except Exception as e:
        raise KeyFormatError(f"Invalid public key: {e}") from e

    try:
        jwe_token = jwe.JWE(
            plaintext=json.dumps(data).encode("utf-8"),
            protected={
                "alg": ALGORITHM_KEY_ENC,
                "enc": ALGORITHM_CONTENT_ENC,
            },
        )
        jwe_token.add_recipient(public_jwk)
        return jwe_token.serialize(compact=True)
    except Exception as e:
        raise EncryptionError(f"JWE Encryption failed: {e}") from e


def decrypt(encrypted_data: str, private_key_pem: str) -> dict:
    """
    Decrypts a JWE compact token into a dictionary using an RSA private key.

    Args:
        encrypted_data (str): Compact JWE token.
        private_key_pem (str): RSA private key in PEM format.

    Returns:
        dict: Decrypted dictionary payload.

    Raises:
        KeyFormatError: If the private key is invalid.
        DecryptionError: If decryption fails.
    """
    try:
        private_jwk = jwk.JWK.from_pem(private_key_pem.encode("utf-8"))
    except Exception as e:
        raise KeyFormatError(f"Invalid private key: {e}") from e

    try:
        jwe_token = jwe.JWE()
        jwe_token.deserialize(encrypted_data, key=private_jwk)
        return json.loads(jwe_token.payload.decode("utf-8"))
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e


def __dir__():
    return sorted(
        name for name in globals()
        if name not in {
            "json", "jwk", "jwe", "ALGORITHM_KEY_ENC", "ALGORITHM_CONTENT_ENC"
        }
    )
