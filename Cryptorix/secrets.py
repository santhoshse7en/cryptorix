import json
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .exceptions import CryptorixError, SecretManagerError

__all__ = ["get_secret_dict", "get_secret_value"]

# Initialize the Secrets Manager client
REGION_NAME = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
secret_manager_client = boto3.client("secretsmanager", region_name=REGION_NAME)


def get_secret_dict(secret_name: str) -> dict[str, str]:
    """
    Fetch the full secret from AWS Secrets Manager and parse it as a dictionary.

    Args:
        secret_name (str): The secret name or full ARN.

    Returns:
        Dict[str, str]: Parsed secret.

    Raises:
        SecretManagerError: On retrieval or parsing failure.
    """
    try:
        response = secret_manager_client.get_secret_value(SecretId=secret_name)
        secret_string = response.get("SecretString")

        if not secret_string:
            raise SecretManagerError(f"Secret '{secret_name}' is empty or missing.")

        return json.loads(secret_string)

    except CryptorixError:
        raise
    except (BotoCoreError, ClientError, json.JSONDecodeError) as e:
        raise SecretManagerError(f"Failed to retrieve secret '{secret_name}': {e}") from e


def get_secret_value(secret_name: str, key: str) -> str:
    """
    Retrieve a specific key's value from a secret in AWS Secrets Manager.

    Args:
        secret_name (str): The secret name or ARN.
        key (str): The key within the secret to fetch.

    Returns:
        str: Value associated with the key.

    Raises:
        SecretManagerError: If key is missing or retrieval fails.
    """
    try:
        secret = get_secret_dict(secret_name)
        value = secret.get(key)

        if not value:
            raise SecretManagerError(f"Key '{key}' not found or empty in secret '{secret_name}'.")

        return value
    except SecretManagerError:
        raise
    except Exception as e:
        raise SecretManagerError(
            f"Failed to retrieve key '{key}' from secret '{secret_name}': {e}") from e


def __dir__():
    return sorted(
        name for name in globals()
        if name not in {
            "json", "os", "boto3", "BotoCoreError", "ClientError", "REGION_NAME",
            "secret_manager_client"
        }
    )
