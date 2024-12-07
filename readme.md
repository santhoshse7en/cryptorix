# Cryptorix

**Cryptorix** is a Python package that provides robust encryption and decryption mechanisms
using JSON Web Encryption (JWE), Hybrid Encryption, AWS KMS, and AWS Secrets Manager.
It leverages both symmetric (AES) and asymmetric (RSA) encryption techniques to ensure the
confidentiality and integrity of your data. The package also integrates with
AWS KMS and Secrets Manager to manage encryption keys securely.

## Table of Contents

* [Overview](#overview)
* [Modules](#modules)
    * [JWE (JSON Web Encryption)](#jwe-json-web-encryption)
    * [Hybrid Encryption](#hybrid-encryption)
    * [KMS (Key Management System)](#kms-key-management-system)
    * [Secrets Manager](#secrets-manager)
* [Installation](#installation)
* [Usage](#usage)
* [Exceptions](#exceptions)
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

### Encrypting Data (JWE):

This function encrypts a dictionary payload using RSA to encrypt the AES key and AES-GCM for content
encryption.

```python
from Cryptorix.jwe import encrypt

# Input data
api_response = {"user": "John Doe", "transaction_id": "123456", "status": "completed"}
secret_name = "your_secret_name"
secret_key = "your_secret_key"
kms_id = "your_kms_key_id"

try:
    # Call to encrypt to create the JWE token
    jwe_token = encrypt(api_response, secret_name, secret_key, kms_id)
    print("Generated JWE Token:", jwe_token)
except Exception as e:
    print(f"Error during encryption: {e}")
```

### Decrypting Data (JWE):

This function decrypts the JWE payload back into its original dictionary form using RSA decryption.

```python
from Cryptorix.jwe import decrypt

# JWE token to decrypt
jwe_token = "your-encrypted-jwe-token"

secret_name = "your-secret-name"  # AWS Secrets Manager secret name
secret_key = "private-key"  # Key name in the secret (private key)
kms_id = "your-kms-key-id"  # AWS KMS key ID

# Decrypt data using JWE
decrypted_payload = decrypt(jwe_token, secret_name, secret_key, kms_id)
print("Decrypted Payload:", decrypted_payload)
```

### Encrypting Data (Hybrid Encryption):

You can use the encrypt_data function to encrypt your sensitive data.

```python
from Cryptorix.hybrid_encryption import encrypt

# Input data to encrypt
api_response = {"username": "admin", "password": "secure_password"}
secret_name = "your_secret_name"
secret_key = "your_secret_key"
kms_id = "your_kms_key_id"

try:
    # Encrypt the data
    result = encrypt(api_response, secret_name, secret_key, kms_id)
    print("Encrypted Data:", result["encryptedData"])
    print("Encrypted Key:", result["encryptedKey"])
except Exception as e:
    print(f"Error during encryption: {e}")
```

### Decrypting Data (Hybrid Encryption):

You can use the decrypt_data function to decrypt the previously encrypted data.

```python
from Cryptorix.hybrid_encryption import decrypt

# Input data to decrypt
encrypted_data = "your_base64_encoded_encrypted_data"
encrypted_key = "your_base64_encoded_encrypted_key"
secret_name = "your_secret_name"
secret_key = "your_secret_key"
kms_id = "your_kms_key_id"

try:
    # Decrypt the data
    decrypted_response = decrypt(encrypted_data, encrypted_key, secret_name, secret_key, kms_id)
    print("Decrypted Response:", decrypted_response)
except Exception as e:
    print(f"Error during decryption: {e}")
```

### Encrypting Data (KMS):

This function encrypts a plaintext string using AWS KMS and returns the encrypted value encoded as a
Base64 string.

```python
from Cryptorix.kms import encrypt

# Input data
plaintext = "your-sensitive-data"
kms_id = "your_kms_key_id"

try:
    # Call to encrypt the plaintext
    encrypted_value = encrypt(plaintext, kms_id)
    print("Encrypted value (base64 encoded):", encrypted_value)
except Exception as e:
    print(f"Error during encryption: {e}")
```

### Decrypting Data (KMS):

This function decrypts a KMS-encrypted base64-encoded string back to its original plaintext form.

```python
from Cryptorix.kms import decrypt

# Input data
encrypted_value = "your_base64_encoded_encrypted_value_here"
lambda_function_name = "your_lambda_function_name"
kms_id = "your_kms_key_id"

try:
    # Call to decrypt the KMS-encrypted value
    decrypted_value = decrypt(encrypted_value, lambda_function_name, kms_id)
    print("Decrypted value:", decrypted_value)
except Exception as e:
    print(f"Error during decryption: {e}")
```

### Retrieve RSA Key:

This function retrieves and decrypts the RSA key from AWS Secrets Manager using AWS KMS.

```python
from Cryptorix.secrets import get_rsa_key

# Input data
secret_name = "your_secret_name"
secret_key = "your_secret_key"
kms_id = "your_kms_key_id"

try:
    # Call to get_rsa_key to retrieve and decrypt the RSA key
    rsa_key = get_rsa_key(secret_name, secret_key, kms_id)
    print("Decrypted RSA key:", rsa_key)
except Exception as e:
    print(f"Error while fetching RSA key: {e}")
```

### Retrieve Secrets:

This function retrieves a specific key from AWS Secrets Manager without decryption.

```python
from Cryptorix.secrets import get_secrets

# Input data
secret_name = "your_secret_name"
secret_key = "your_secret_key"

try:
    # Call to get_secrets to fetch only the specific key value
    secret_data = get_secrets(secret_name, secret_key)
    print("Secret data retrieved:", secret_data)
except Exception as e:
    print(f"Error while retrieving secrets: {e}")
```

### Retrieve Secrets:

This function decrypts a given base64-encoded ciphertext using AWS KMS directly.

```python
from Cryptorix.secrets import decrypt_kms_ciphertext

# Input data
kms_id = "your_kms_key_id"
ciphertext = "your_base64_encoded_ciphertext"

try:
    # Call to decrypt_kms_ciphertext to decrypt the base64 KMS ciphertext
    decrypted_data = decrypt_kms_ciphertext(ciphertext, kms_id)
    print("Decrypted KMS ciphertext:", decrypted_data)
except Exception as e:
    print(f"Error while decrypting KMS ciphertext: {e}")
```

### Exceptions

Cryptorix provides custom exceptions for error handling:

* **HybridEncryptionError**: Raised during hybrid encryption/decryption failures.
* **JWEError**: Raised during JWE encryption/decryption failures.
* **KMSDecryptionError**: Raised if decryption via AWS KMS fails.
* **KMSEncryptionError**: Raised if encryption via AWS KMS fails.
* **SecretRetrievalError**: Raised if secrets cannot be retrieved or decrypted from AWS Secrets
  Manager.

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