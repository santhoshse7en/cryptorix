import json
import os
from base64 import b64decode, b64encode
from typing import Union

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .exceptions import EncryptionError, DecryptionError

__all__ = ["encrypt", "decrypt"]

# Set default AWS region
REGION_NAME = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
kms_client = boto3.client("kms", region_name=REGION_NAME)


def encrypt(plaintext: str, kms_key_id: str) -> str:
    """
    Encrypt a plaintext string using AWS KMS and return a base64-encoded ciphertext.

    Args:
        plaintext (str): Plaintext to encrypt.
        kms_key_id (str): AWS KMS Key ID or ARN.

    Returns:
        str: Base64-encoded encrypted string.

    Raises:
        EncryptionError: If encryption fails.
    """
    try:
        response = kms_client.encrypt(
            KeyId=kms_key_id,
            Plaintext=plaintext.encode("utf-8")
        )
        encrypted_blob = response["CiphertextBlob"]
        return b64encode(encrypted_blob).decode("utf-8")
    except (BotoCoreError, ClientError) as e:
        raise EncryptionError(f"KMS encryption failed: {e}") from e


def decrypt(ciphertext_b64: str) -> Union[str, dict]:
    """
    Decrypt a base64-encoded ciphertext using AWS KMS.

    Args:
        ciphertext_b64 (str): Base64-encoded encrypted string.

    Returns:
        Union[str, dict]: Decrypted plaintext or parsed JSON dictionary.

    Raises:
        DecryptionError: If decryption fails.
    """
    try:
        decrypted_response = kms_client.decrypt(
            CiphertextBlob=b64decode(ciphertext_b64)
        )
        plaintext = decrypted_response["Plaintext"].decode("utf-8")
        return json.loads(plaintext) if plaintext.strip().startswith("{") else plaintext
    except (BotoCoreError, ClientError, json.JSONDecodeError) as e:
        raise DecryptionError(f"KMS decryption failed: {e}") from e


def __dir__():
    return sorted(
        name for name in globals()
        if name not in {
            "b64decode", "b64encode", "boto3", "Union", "json", "os",
            "BotoCoreError", "ClientError", "REGION_NAME", "kms_client"
        }
    )
