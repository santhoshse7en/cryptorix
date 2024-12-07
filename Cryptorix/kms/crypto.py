import json
import os
from base64 import b64decode, b64encode

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
        kms_id (str): The KMS Key ID used for encryption.
        plaintext (str): The plaintext string to encrypt.

    Returns:
        str: The encrypted value as a base64-encoded string.

    Raises:
        KMSEncryptionError: If the encryption process fails.
    """
    try:
        # Encrypt the plaintext using AWS KMS
        response = kms_client.encrypt(KeyId=kms_id, Plaintext=plaintext.encode("utf-8"))

        # Encode the ciphertext blob as a base64 string
        ciphertext = b64encode(response["CiphertextBlob"]).decode("utf-8")
        return ciphertext

    except Exception as error:
        raise KMSEncryptionError(
            error=str(error),
            error_code="ENCRYPTION_ERROR",
            function_name="encrypt",
            context={"kms_id": kms_id}
        )


def decrypt(encrypted_value: str, lambda_function_name: str, kms_id: str) -> dict:
    """
    Decrypts a KMS-encrypted base64-encoded string.

    Args:
        kms_id (str): The KMS Key ID used for decryption.
        lambda_function_name (str): The Lambda function name for encryption context.
        encrypted_value (str): The base64-encoded encrypted string to decrypt.

    Returns:
        dict: The decrypted value as a dictionary.

    Raises:
        KMSDecryptionError: If the decryption process fails.
    """
    try:
        # Decrypt the encrypted value using AWS KMS
        decrypted_response = kms_client.decrypt(
            KeyId=kms_id,
            CiphertextBlob=b64decode(encrypted_value),
            EncryptionContext={"LambdaFunctionName": lambda_function_name}
        )

        # Decode and parse the decrypted plaintext
        decrypted_value = json.loads(decrypted_response["Plaintext"].decode("utf-8"))
        return decrypted_value

    except Exception as error:
        raise KMSDecryptionError(
            error=str(error),
            error_code="DECRYPTION_ERROR",
            function_name="decrypt",
            context={"kms_id": kms_id, "lambda_function_name": lambda_function_name}
        ) from error
