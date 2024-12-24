import json
import os
from base64 import b64decode, b64encode
from typing import Union

import boto3

from Cryptorix.kms.exceptions import KMSDecryptionError, KMSEncryptionError

# Set default AWS region, falling back to "ap-south-1" if not set
REGION_NAME = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")

# Initialize the AWS KMS client
kms_client = boto3.client(service_name="kms", region_name=REGION_NAME)


def encrypt(plaintext: str, kms_id: str) -> str:
    """
    Encrypts a plaintext string using AWS KMS.

    Args:
        plaintext (str): The plaintext string to encrypt.
        kms_id (str): The KMS Key ID used for encryption.

    Returns:
        str: The encrypted value as a base64-encoded string.

    Raises:
        KMSEncryptionError: If the encryption process fails.
    """
    try:
        encrypted_response = kms_client.encrypt(
            KeyId=kms_id,
            Plaintext=plaintext.encode("utf-8")
        )
        return b64encode(encrypted_response["CiphertextBlob"]).decode("utf-8")
    except Exception as error:
        raise KMSEncryptionError(
            error=str(error),
            error_code="ENCRYPTION_ERROR",
            function_name="encrypt",
            context={"kms_id": kms_id}
        ) from error


def decrypt(encrypted_value: str, kms_id: str) -> Union[dict, str]:
    """
    Decrypts a KMS-encrypted base64-encoded string.

    Args:
        encrypted_value (str): The base64-encoded encrypted string to decrypt.
        kms_id (str): The KMS Key ID used for decryption.

    Returns:
        Union[dict, str]: The decrypted value as a dictionary or string.

    Raises:
        KMSDecryptionError: If the decryption process fails.
    """
    try:
        decrypted_response = kms_client.decrypt(
            KeyId=kms_id,
            CiphertextBlob=b64decode(encrypted_value)
        )
        return __parse_output(decrypted_response["Plaintext"].decode("utf-8"))
    except Exception as error:
        raise KMSDecryptionError(
            error=str(error),
            error_code="DECRYPTION_ERROR",
            function_name="decrypt",
            context={
                "kms_id": kms_id,
                "encrypted_value": encrypted_value[:30] + "..."  # Mask long values for logs
            }
        ) from error


def __parse_output(response: str) -> Union[dict, str]:
    """
    Parses the decrypted response into a dictionary if possible, otherwise returns it as a string.

    Args:
        response (str): The decrypted response string.

    Returns:
        Union[dict, str]: Parsed dictionary or the original string.
    """
    try:
        if response.strip().startswith("{"):
            return json.loads(response)
        return response
    except json.JSONDecodeError:
        return response
