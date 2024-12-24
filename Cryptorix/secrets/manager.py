import json
import os
from typing import Dict

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from Cryptorix.kms import decrypt
from Cryptorix.secrets.exceptions import SecretRetrievalError

# Set default AWS region, falling back to "ap-south-1" if not set
REGION_NAME = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")

# Initialize AWS clients
secret_manager_client = boto3.client(service_name="secretsmanager", region_name=REGION_NAME)
kms_client = boto3.client(service_name="kms", region_name=REGION_NAME)


def retrieve_secret_key(secret_name: str, secret_key: str) -> str:
    """
    Retrieve and decrypt a specific key from AWS Secrets Manager.

    Args:
        secret_name (str): The name or ARN of the secret in Secrets Manager.
        secret_key (str): The key within the secret to retrieve.

    Returns:
        str: The decrypted RSA key as plaintext.

    Raises:
        SecretRetrievalError: If the secret retrieval or key extraction fails.
    """
    try:
        # Fetch the secret dictionary from Secrets Manager
        secret_dict = get_secrets(secret_name, secret_key)

        # Retrieve the specified key's value
        plain_text = secret_dict.get(secret_key)
        if not plain_text:
            raise SecretRetrievalError(
                error=f"Key '{secret_key}' not found in secret '{secret_name}'.",
                error_code="KEY_NOT_FOUND",
                function_name="retrieve_secret_key",
                context={"secret_name": secret_name, "secret_key": secret_key}
            )

        return plain_text

    except SecretRetrievalError as error:
        # Log and re-raise the SecretRetrievalError
        raise SecretRetrievalError(
            error=str(error),
            error_code="SECRET_RETRIEVAL_FAILED",
            function_name="retrieve_secret_key",
            context={"secret_name": secret_name, "secret_key": secret_key}
        ) from error

    except Exception as error:
        # Handle any unexpected exceptions
        raise SecretRetrievalError(
            error=f"Unexpected error occurred: {str(error)}",
            error_code="UNEXPECTED_ERROR",
            function_name="retrieve_secret_key",
            context={"secret_name": secret_name, "secret_key": secret_key}
        ) from error


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
        SecretRetrievalError: If secret retrieval fails.
        KMSDecryptionError: If KMS decryption fails.
    """
    try:
        # Retrieve the secret dictionary from Secrets Manager
        secret_dict = get_secrets(secret_name, secret_key)

        # Extract the ciphertext associated with the provided key
        ciphertext = secret_dict.get(secret_key)
        if not ciphertext:
            raise SecretRetrievalError(
                error=f"Key '{secret_key}' not found in the secret '{secret_name}'.",
                error_code="KEY_NOT_FOUND",
                function_name="get_rsa_key",
                context={"secret_name": secret_name, "secret_key": secret_key}
            )

        # Decrypt the ciphertext using AWS KMS
        rsa_key = decrypt(encrypted_value=ciphertext, kms_id=kms_id)
        return rsa_key

    except Exception as error:
        raise SecretRetrievalError(
            error=str(error),
            error_code="SECRET_OPERATION_FAILED",
            function_name="retrieve_decrypted_secret_key",
            context={"secret_name": secret_name, "secret_key": secret_key, "kms_id": kms_id}
        ) from error


def get_secrets(secret_name: str, secret_key: str) -> Dict[str, str]:
    """
    Retrieve and parse a specific key from the secret stored in AWS Secrets Manager.

    Args:
        secret_name (str): The name or ARN of the secret in Secrets Manager.
        secret_key (str): The specific key within the secret to retrieve.

    Returns:
        dict: The complete secret as a dictionary.

    Raises:
        SecretRetrievalError: If retrieval or parsing of the secret fails.
    """
    try:
        # Fetch the secret value from AWS Secrets Manager
        response = secret_manager_client.get_secret_value(SecretId=secret_name)

        # Extract the "SecretString" from the response; default to an empty JSON-like string
        secret_string = response.get("SecretString", "{}").strip()

        # Ensure the secret string is not empty
        if not secret_string:
            raise SecretRetrievalError(
                error=f"The secret '{secret_name}' is empty or malformed.",
                error_code="EMPTY_SECRET",
                function_name="get_secrets",
                context={"secret_name": secret_name}
            )

        # Parse the secret string as JSON
        secret_dict = json.loads(secret_string)

        # Ensure the desired key is present in the parsed secret
        if secret_key not in secret_dict:
            raise SecretRetrievalError(
                error=f"Key '{secret_key}' not found in secret '{secret_name}'.",
                error_code="KEY_NOT_PRESENT",
                function_name="get_secrets",
                context={"secret_name": secret_name, "secret_key": secret_key}
            )

        # Return the full parsed secret as a dictionary
        return secret_dict

    except (ClientError, BotoCoreError) as aws_error:
        raise SecretRetrievalError(
            error=str(aws_error),
            error_code="SECRET_RETRIEVAL_FAILED",
            function_name="get_secrets",
            context={"secret_name": secret_name, "secret_key": secret_key}
        ) from aws_error
    except json.JSONDecodeError as json_error:
        raise SecretRetrievalError(
            error=str(json_error),
            error_code="JSON_DECODE_ERROR",
            function_name="get_secrets",
            context={"secret_name": secret_name}
        ) from json_error
