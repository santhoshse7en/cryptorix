# Cryptorix

**Cryptorix** is a Python package that provides robust encryption and decryption mechanisms
using JSON Web Encryption (JWE), Hybrid Encryption, AWS KMS, and AWS Secrets Manager.
It leverages both symmetric (AES) and asymmetric (RSA) encryption techniques to ensure the
confidentiality and integrity of your data. The package also integrates with
AWS KMS and Secrets Manager to manage encryption keys securely.

## Table of Contents

* [Overview](#overview)
* [Modules](#modules)
    * [JWE](#jwe-json-web-encryption)
    * [Hybrid Encryption](#hybrid-encryption)
    * [KMS](#kms-key-management-system)
    * [Secrets Manager](#secrets-manager)
* [Installation](#installation)
* [Usage](#usage)
* [Exceptions](#exceptions)
* [Logging](#logging)
* [AWS Permissions](#aws-permissions)
* [Dependencies](#dependencies)
* [License](#license)
* [Contributing](#contributing)
* [Authors](#authors)

## Overview

Cryptorix allows you to encrypt and decrypt data using industry-standard encryption algorithms,
focusing on JWE for secure token exchange, Hybrid Encryption for data security, and
AWS services (KMS and Secrets Manager) for key management. The package ensures seamless integration
with AWS services for encryption at rest and in transit.

## Modules

### JWE (JSON Web Encryption)

This module facilitates the encryption and decryption of data using the JWE standard,
combining RSA encryption for key management and AES-GCM encryption for content.

**Functions:**

* `encrypt(api_response, secret_name, secret_key, kms_id)`: Encrypts a dictionary into a JWE token
  using RSA encryption for the AES key and AES-GCM for the content.
* `decrypt(jwe_payload, secret_name, secret_key, kms_id)`: Decrypts a JWE token into its original
  dictionary form using the RSA private key.

### Hybrid Encryption

This module implements hybrid encryption using AES for data encryption and RSA for key encryption.
The encrypted data is Base64-encoded for secure transmission.

**Functions:**

* `encrypt_data(api_response, secret_name, secret_key, kms_id)`: Encrypts data using AES-GCM for
  encryption and RSA for encrypting the AES key.
* `decrypt_data(encrypted_data, encrypted_key, secret_name, secret_key, kms_id)`: Decrypts the
  encrypted data using RSA and AES-GCM.

### KMS (Key Management System)

This module provides AWS KMS-based encryption and decryption of data.
It integrates with AWS KMS to securely manage encryption keys.

**Functions:**

* `decrypt(encrypted_value, lambda_function_name, kms_id)`: Decrypts a KMS-encrypted,
  base64-encoded string.
* `encrypt(plaintext, kms_id)`: Encrypts a plaintext string using AWS KMS and returns the encrypted
  value as a base64 string.

### Secrets Manager

This module interacts with AWS Secrets Manager to retrieve and decrypt secrets,
ensuring that sensitive information is handled securely.

**Functions:**

* `get_rsa_key(secret_name, secret_key, kms_id)`: Retrieves and decrypts the RSA key from
  AWS Secrets Manager using KMS.
* `get_secrets(secret_name, secret_key)`: Retrieves a specific key from a secret stored in
  AWS Secrets Manager.
* `decrypt_kms_ciphertext(ciphertext, kms_id)`: Decrypts base64-encoded ciphertext using AWS KMS.

## Installation

To install the Cryptorix package, use pip:

```bash
pip install Cryptorix
```

You also need to install dependencies such as boto3, pycryptodome, and jwcrypto.
You can install them with:

```bash
pip install boto3 pycryptodome jwcrypto
```

## Usage

Here is a basic example of how to use the package:

### Encrypting Data (Hybrid Encryption):

```python
from Cryptorix.hybrid_encryption import encrypt

# Data to encrypt
api_response = {"user": "John Doe", "account_id": "123456"}

kms_id = "your-kms-key-id"  # AWS KMS key ID
secret_name = "your-secret-name"  # AWS Secrets Manager secret name
secret_key = "private-key"  # Key name in the secret (private key)

# Encrypt data using hybrid encryption
encrypted_data = encrypt(api_response, secret_name, secret_key, kms_id)
print("Encrypted Data:", encrypted_data)
```

### Encrypting Data (JWE):

```python
from Cryptorix.jwe import encrypt

# Data to encrypt
api_response = {"user": "John Doe", "account_id": "123456"}

kms_id="your-kms-key-id"  # AWS KMS key ID to use for encryption
secret_name="your-secret-name"  # AWS Secrets Manager secret name
secret_key="private-key"  # Key name in the secrets (private key)

# Encrypt data using JWE
jwe_token = encrypt(api_response, secret_name, secret_key, kms_id)
print("Encrypted JWE Token:", jwe_token)
```

### Encrypting Data (KMS):

```python
from Cryptorix.kms import encrypt

kms_id = "your-kms-key-id"  # AWS KMS key ID to use for encryption
plaintext = "Sensitive Data"  # The plaintext data to encrypt

# Encrypt the plaintext using AWS KMS
kms_encrypted_data = encrypt(plaintext, kms_id)
print("Encrypted Data:", kms_encrypted_data)

```

### Decrypting Data (Hybrid Encryption):

```python
from Cryptorix.hybrid_encryption import decrypt

# AES-encrypted data & RSA-encrypted AES key to decrypt
encrypted_data = "your-encrypted-data"
encrypted_key = "your-encrypted-key"

kms_id = "your-kms-key-id"  # AWS KMS key ID to use for encryption
secret_name = "your-secret-name"  # AWS Secrets Manager secret name
secret_key = "private-key"  # Key name in the secret (private key)

# Decrypt data using hybrid encryption
decrypted_data = decrypt(encrypted_data, encrypted_key, secret_name, secret_key, kms_id)
print("Decrypted Data:", decrypted_data)

```

### Decrypting Data (JWE):

```python
from Cryptorix.jwe import decrypt

# JWE token to decrypt
jwe_token = "your-encrypted-jwe-token"

kms_id = "your-kms-key-id"  # AWS KMS key ID to use for encryption
secret_name = "your-secret-name"  # AWS Secrets Manager secret name
secret_key = "private-key"  # Key name in the secret (private key)

# Decrypt data using JWE
decrypted_payload = decrypt(jwe_token, secret_name, secret_key, kms_id)
print("Decrypted Payload:", decrypted_payload)
```

### Decrypting Data (KMS):

```python
from Cryptorix.kms import decrypt

kms_id = "your-kms-key-id"  # AWS KMS key ID to use for encryption
encrypted_value = "your-encrypted-data"  # The encrypted data (e.g., Base64 string)
lambda_function_name = "your-lambda-function"  # Name of the AWS Lambda function

# Decrypt KMS-encrypted data
decrypted_value = decrypt(encrypted_value, lambda_function_name, kms_id)
print("Decrypted Value:", decrypted_value)
```

### Exceptions

Cryptorix provides custom exceptions for error handling:

* **HybridEncryptionError**: Raised during hybrid encryption/decryption failures.
* **JWEError**: Raised during JWE encryption/decryption failures.
* **KMSDecryptionError**: Raised if decryption via AWS KMS fails.
* **KMSEncryptionError**: Raised if encryption via AWS KMS fails.
* **SecretRetrievalError**: Raised if secrets cannot be retrieved or decrypted from AWS Secrets
  Manager.

## Logging

Cryptorix uses a logging system to capture and record exceptions. The log messages provide useful
information, including the function name, error messages, and the relevant AWS KMS key ID.

Example of logging configuration:

```python
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
```

This will capture all error-level logs related to encryption and decryption operations.

## AWS Permissions

Ensure the following permissions are assigned to your AWS IAM role or user:

* KMS Permissions:
    * `kms:Encrypt`
    * `kms:Decrypt`
* Secrets Manager Permissions:
    * `secretsmanager:GetSecretValue`

## Dependencies

The package requires the following dependencies:

* [`jwcrypto`](https://pypi.org/project/jwcrypto/): Implementation of JOSE Web standards.
* [`pycryptodome`](https://pypi.org/project/pycryptodome/): Cryptographic library for Python.
* [`boto3`](https://pypi.org/project/boto3/): AWS SDK for Python.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Submit issues or pull requests to enhance the package. For major changes,
please open a discussion first.

## Authors

M Santhosh Kumar
Initial work
santhoshse7en@gmail.com