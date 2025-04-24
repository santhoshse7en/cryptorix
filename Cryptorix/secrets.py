import json
import os
from typing import Dict

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from Cryptorix.exceptions import EncryptionError
from Cryptorix.kms import decrypt

# Set default AWS region, falling back to "ap-south-1" if not set
REGION_NAME = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")

# Initialize AWS clients
secret_manager_client = boto3.client(service_name="secretsmanager", region_name=REGION_NAME)
kms_client = boto3.client(service_name="kms", region_name=REGION_NAME)


def _handle_error(error: Exception, function_name: str, context: Dict) -> None:
    """Helper function for consistent error handling."""
    raise EncryptionError(
        error=str(error),
        error_code="SECRET_OPERATION_FAILED",
        function_name=function_name,
        context=context
    ) from error


def get_secrets(secret_name: str) -> Dict[str, str]:
    """
    Fetch and parse the secret from AWS Secrets Manager.

    Args:
        secret_name (str): The name or ARN of the secret in Secrets Manager.

    Returns:
        dict: The parsed secret as a dictionary.

    Raises:
        EncryptionError: If retrieval or parsing of the secret fails.
    """
    try:
        response = secret_manager_client.get_secret_value(SecretId=secret_name)
        secret_string = response.get("SecretString", "{}").strip()

        if not secret_string:
            raise EncryptionError(
                error=f"The secret '{secret_name}' is empty or malformed.",
                error_code="EMPTY_SECRET",
                function_name="_get_secret_value",
                context={"secret_name": secret_name}
            )

        return json.loads(secret_string)
    except (ClientError, BotoCoreError) as aws_error:
        _handle_error(
            error=aws_error,
            function_name="_get_secret_value",
            context={"secret_name": secret_name}
        )
    except json.JSONDecodeError as json_error:
        _handle_error(
            error=json_error,
            function_name="_get_secret_value",
            context={"secret_name": secret_name}
        )


def retrieve_secret_key(secret_name: str, secret_key: str) -> str:
    """
    Retrieve a specific key from a secret in AWS Secrets Manager.

    Args:
        secret_name (str): The name or ARN of the secret in Secrets Manager.
        secret_key (str): The key within the secret to retrieve.

    Returns:
        str: The decrypted RSA key as plaintext.

    Raises:
        EncryptionError: If the secret or key is not found or any error occurs.
    """
    try:
        secret_dict = get_secrets(secret_name)
        plain_text = secret_dict.get(secret_key)

        if not plain_text:
            raise EncryptionError(
                error=f"Key '{secret_key}' not found in secret '{secret_name}'.",
                error_code="KEY_NOT_FOUND",
                function_name="retrieve_secret_key",
                context={"secret_name": secret_name, "secret_key": secret_key}
            )

        return plain_text
    except Exception as error:
        _handle_error(
            error=error,
            function_name="retrieve_secret_key",
            context={"secret_name": secret_name, "secret_key": secret_key}
        )


def retrieve_decrypted_secret_key(secret_name: str, secret_key: str, kms_id: str) -> str:
    """
    Retrieve and decrypt the RSA key from AWS Secrets Manager using KMS.

    Args:
        secret_name (str): The name or ARN of the secret in Secrets Manager.
        secret_key (str): The specific key within the secret to decrypt.
        kms_id (str): The KMS Key ID used for decryption.

    Returns:
        str: The decrypted RSA key as a plaintext string.

    Raises:
        EncryptionError: If retrieval or decryption fails.
    """
    try:
        secret_dict = get_secrets(secret_name)
        ciphertext = secret_dict.get(secret_key)

        if not ciphertext:
            raise EncryptionError(
                error=f"Key '{secret_key}' not found in secret '{secret_name}'.",
                error_code="KEY_NOT_FOUND",
                function_name="retrieve_decrypted_secret_key",
                context={"secret_name": secret_name, "secret_key": secret_key}
            )

        # Decrypt the ciphertext using AWS KMS
        return decrypt(encrypted_value=ciphertext, kms_id=kms_id)
    except Exception as error:
        _handle_error(error, "retrieve_decrypted_secret_key", {
            "secret_name": secret_name,
            "secret_key": secret_key,
            "kms_id": kms_id
        })
