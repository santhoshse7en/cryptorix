import base64
import json
import os
from typing import Dict

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from Cryptorix.logger import logger
from Cryptorix.secrets.exceptions import SecretRetrievalError, KMSDecryptionError

# Set default AWS region, falling back to "ap-south-1" if not set
REGION_NAME = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")

# Initialize AWS clients
secret_manager_client = boto3.client(service_name="secretsmanager", region_name=REGION_NAME)
kms_client = boto3.client(service_name="kms", region_name=REGION_NAME)


def get_rsa_key(secret_name: str, secret_key: str, kms_id: str) -> str:
    """
    Retrieve and decrypt the RSA key from AWS Secrets Manager using KMS.

    Args:
        secret_name (str): The name or ARN of the secret in Secrets Manager.
        secret_key (str): The specific key within the secret to decrypt.
        kms_id (str): The KMS Key ID used for decryption.

    Returns:
        str: The decrypted RSA key as a plaintext string.

    Raises:
        SecretRetrievalError: If secret retrieval or decryption fails.
        InterruptedError: If a specific retrieval or decryption error occurs.
    """
    try:
        # Retrieve the secret dictionary from Secrets Manager
        secret_dict = get_secrets(secret_name, secret_key)

        # Extract the ciphertext associated with the provided key
        ciphertext = secret_dict.get(secret_key)
        if not ciphertext:
            raise SecretRetrievalError(
                message=f"Key '{secret_key}' not found in the secret '{secret_name}'.",
                error_code="KEY_NOT_FOUND",
                function_name="get_rsa_key"
            )

        # Decrypt the ciphertext using AWS KMS
        rsa_key = decrypt_kms_ciphertext(kms_id, ciphertext)
        return rsa_key

    except (SecretRetrievalError, KMSDecryptionError) as specific_error:
        # Log and re-raise specific errors for diagnostics
        logger.error(f"Specific error in get_rsa_key: {specific_error}")
        raise InterruptedError(specific_error)

    except Exception as error:
        # Log and re-raise unexpected exceptions as SecretRetrievalError
        logger.exception(f"Unexpected error in get_rsa_key: {error}")
        raise SecretRetrievalError(
            message="Unexpected error occurred during RSA key retrieval.",
            error_code="UNEXPECTED_ERROR",
            function_name="get_rsa_key"
        )


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
                message=f"The secret '{secret_name}' is empty or malformed.",
                error_code="EMPTY_SECRET",
                function_name="get_secrets"
            )

        # Parse the secret string as JSON
        secret_dict = json.loads(secret_string)

        # Ensure the desired key is present in the parsed secret
        if secret_key not in secret_dict:
            raise SecretRetrievalError(
                message=f"Key '{secret_key}' not found in secret '{secret_name}'.",
                error_code="KEY_NOT_PRESENT",
                function_name="get_secrets"
            )

        # Return the full parsed secret as a dictionary
        return secret_dict

    except (ClientError, BotoCoreError) as aws_error:
        # Handle AWS-related exceptions
        logger.error(f"Error accessing Secrets Manager for '{secret_name}': {aws_error}")
        raise SecretRetrievalError(
            message=f"Error accessing AWS Secrets Manager: {aws_error}",
            error_code="SECRET_RETRIEVAL_FAILED",
            function_name="get_secrets"
        )

    except json.JSONDecodeError as json_error:
        # Handle JSON parsing exceptions
        logger.error(f"Failed to parse secret JSON for '{secret_name}': {json_error}")
        raise SecretRetrievalError(
            message=f"Error decoding secret JSON: {json_error}",
            error_code="JSON_DECODE_ERROR",
            function_name="get_secrets"
        )


def decrypt_kms_ciphertext(kms_id: str, ciphertext: str) -> str:
    """
    Decrypt a base64-encoded ciphertext using AWS KMS.

    Args:
        kms_id (str): The KMS Key ID used for decryption.
        ciphertext (str): Base64-encoded ciphertext to decrypt.

    Returns:
        str: Decrypted plaintext string.

    Raises:
        KMSDecryptionError: If decryption fails due to AWS errors or unexpected issues.
    """
    try:
        # Decode the ciphertext from Base64 format
        ciphertext_blob = base64.b64decode(ciphertext)

        # Perform decryption using AWS KMS
        response = kms_client.decrypt(CiphertextBlob=ciphertext_blob, KeyId=kms_id)

        # Extract the plaintext and decode it to a string
        plaintext = response["Plaintext"].decode("utf-8")
        return plaintext

    except (ClientError, BotoCoreError) as aws_error:
        # Handle AWS-specific errors during decryption
        logger.error(f"KMS decryption failed for KMS ID '{kms_id}': {aws_error}")
        raise KMSDecryptionError(
            message=f"KMS decryption error: {aws_error}",
            error_code="KMS_DECRYPTION_FAILED",
            function_name="decrypt_kms_ciphertext"
        )

    except Exception as error:
        # Handle any unexpected errors
        logger.exception(f"Unexpected error during KMS decryption for KMS ID '{kms_id}': {error}")
        raise KMSDecryptionError(
            message="Unexpected error occurred during KMS decryption.",
            error_code="UNEXPECTED_DECRYPTION_ERROR",
            function_name="decrypt_kms_ciphertext"
        )
