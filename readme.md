# Cryptorix

**Cryptorix** is a Python package that provides robust encryption and decryption mechanisms
using JSON Web Encryption (JWE), Hybrid Encryption, AWS KMS, and AWS Secrets Manager.
It leverages both symmetric (AES) and asymmetric (RSA) encryption techniques to ensure the
confidentiality and integrity of your data. The package also integrates with
AWS KMS and Secrets Manager to manage encryption keys securely.

## Table of Contents

* [Overview](#overview)
* [Modules](#modules)
    * [AES (Key Management System)](#aes-advanced-encryption-standard-module)
    * [JWE (JSON Web Encryption)](#jwe-json-web-encryption-module)
    * [Hybrid Encryption](#hybrid-encryption-module)
    * [KMS (Key Management System)](#kms-key-management-system-module)
    * [Secrets Manager](#secrets-manager-module)
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
focusing on AES for secure data, JWE for secure token exchange, Hybrid Encryption for data security,
and AWS services (KMS and Secrets Manager) for key management.
The package ensures seamless integration with AWS services for encryption at rest and in transit.

## Modules

### AES (Advanced Encryption Standard) Module

This module provides functionality to securely encrypt and decrypt data using the
AES (Advanced Encryption Standard) algorithm.

**Functions:**

* `encrypt(api_response, secret_name, secret_key, kms_id)`: Encrypts a dictionary (`api_response`)
  using the provided AES key and associated metadata (`secret_name`, `secret_key`, `kms_id`).
* `decrypt(jwe_payload, secret_name, secret_key, kms_id)`: Decrypts an AES-encrypted payload
  (`jwe_payload`) and restores it to its original dictionary format using the
  same AES key & metadata.

### JWE (JSON Web Encryption) Module

This module enables secure data encryption and decryption using the JWE standard,
which combines RSA for key encryption and AES-GCM for encrypting the actual content.

**Functions:**

* `encrypt(api_response, secret_name, secret_key, kms_id)`: Encrypts a dictionary (`api_response`)
  into a JWE token. It uses RSA encryption to protect the AES key and AES-GCM to encrypt the
  payload content.
* `decrypt(jwe_payload, secret_name, secret_key, kms_id)`: Decrypts a JWE token (`jwe_payload`)
  back into its original dictionary form using the associated RSA private key and metadata.

### Hybrid Encryption Module

This module implements hybrid encryption, utilizing AES for encrypting the data and RSA for
encrypting the AES session key. The resulting encrypted data is Base64-encoded, ensuring secure
transmission over communication channels.

**Functions:**

* `encrypt_data(api_response, secret_name, secret_key, kms_id, rsa_padding)`: Encrypts the provided
  data (`api_response`) using a hybrid encryption scheme. AES (in either GCM or CBC mode) is used
  for encrypting the data, while RSA encrypts the AES session key. The encrypted data is then
  Base64-encoded for secure transmission.
* `decrypt_data(encrypted_data, encrypted_key, secret_name, secret_key, kms_id, rsa_padding)`:
  Decrypts the provided Base64-encoded encrypted data (`encrypted_data`) by first using RSA to
  decrypt the AES session key, and then using AES-GCM/CBC to decrypt the actual data.

### KMS (Key Management System) Module

This module integrates with AWS Key Management Service (KMS) to provide secure encryption and
decryption of data, leveraging AWS's managed encryption keys.

**Functions:**

* `encrypt(plaintext, kms_id)`: Encrypts a plaintext string (`plaintext`) using AWS KMS and returns
  the encrypted value as a Base64-encoded string.
* `decrypt(encrypted_value, kms_id)`: Decrypts a KMS-encrypted, Base64-encoded string
  (`encrypted_value`) using the specified KMS key (kms_id).

### Secrets Manager Module

This module interacts with AWS Secrets Manager to securely retrieve and decrypt sensitive
information, such as secrets and credentials, ensuring they are handled safely.

**Functions:**

* `retrieve_decrypted_secret_key(secret_name, secret_key, kms_id)`: Retrieves and decrypts a secret
  key from AWS Secrets Manager, utilizing AWS KMS for decryption.
* `retrieve_secret_key(secret_name, secret_key)`: Retrieves a specific key stored in AWS Secrets
  Manager without decrypting it.
* `get_secrets(ciphertext, kms_id)`: Retrieves a specific secret stored in AWS Secrets Manager
  and decrypts it using the provided KMS key (kms_id).

## Installation

To install the Cryptorix package, use pip:

```bash
pip install Cryptorix
```

## Usage

Here is a basic example of how to use the package:

### 🔐 AES Encryption:

Encrypt a dictionary payload using an AES key to produce a secure, encrypted string.

```python
from Cryptorix.aes import encrypt

# Sample data to encrypt
data_to_encrypt = {
    "user": "John Doe",
    "transaction_id": "123456",
    "status": "completed"
}
aes_key = "your_aes_key"

try:
    # Encrypt the data
    encrypted_data = encrypt(api_response=data_to_encrypt, aes_key=aes_key)
    print("🔒 Encrypted Data:", encrypted_data)
except Exception as error:
    print(f"❌ Encryption Error: {error}")
```

### 🔓 AES Decryption:

Decrypt the AES-encrypted payload using the same AES key to retrieve the original dictionary.

```python
from Cryptorix.aes import decrypt

# Encrypted data string (JWE format)
encrypted_data = "your-encrypted-data"
aes_key = "your_aes_key"

try:
    # Decrypt the data
    decrypted_data = decrypt(encrypted_data=encrypted_data, aes_key=aes_key)
    print("✅ Decrypted Payload:", decrypted_data)
except Exception as error:
    print(f"❌ Decryption Error: {error}")
```

### 🔐 JWE  Encryption:

Encrypts a dictionary payload using AES-GCM for content encryption and RSA to encrypt the AES key.
Key materials are securely retrieved via AWS KMS and Secrets Manager.

```python
from Cryptorix.jwe import encrypt

# Data to encrypt
data_to_encrypt = {
    "user": "John Doe",
    "transaction_id": "123456",
    "status": "completed"
}

# Key management inputs
secret_name = "your_secret_name"  # AWS Secrets Manager name
secret_key = "your_secret_key"  # Key name inside the secret (e.g., public key)
kms_id = "your_kms_key_id"  # AWS KMS Key ID

try:
    # Generate JWE token
    jwe_token = encrypt(
        api_response=data_to_encrypt,
        secret_name=secret_name,
        secret_key=secret_key,
        kms_id=kms_id
    )
    print("🔐 Generated JWE Token:", jwe_token)
except Exception as error:
    print(f"❌ Encryption Error: {error}")
```

### 🔓 JWE Decryption:

Decrypts the JWE token back into its original dictionary form using the corresponding RSA private
key.

```python
from Cryptorix.jwe import decrypt

# Encrypted JWE token
jwe_token = "your-encrypted-jwe-token"

# Key management inputs
secret_name = "your_secret_name"  # AWS Secrets Manager name
secret_key = "private-key"  # Key name in the secret (e.g., private key)
kms_id = "your_kms_key_id"  # AWS KMS Key ID

try:
    # Decrypt the JWE token
    decrypted_data = decrypt(
        jwe_payload=jwe_token,
        secret_name=secret_name,
        secret_key=secret_key,
        kms_id=kms_id
    )
    print("✅ Decrypted Payload:", decrypted_data)
except Exception as error:
    print(f"❌ Decryption Error: {error}")
```

### 🔐 Hybrid Encryption:

Encrypt sensitive data using hybrid encryption: AES-GCM for content encryption and
RSA (via AWS KMS and Secrets Manager) for encrypting the AES key.

```python
from Cryptorix.hybrid import encrypt

# Payload to be encrypted
sensitive_data = {
    "username": "admin",
    "password": "secure_password"
}

# Encryption parameters
secret_name = "your_secret_name"  # AWS Secrets Manager secret name
secret_key = "your_secret_key"  # Key name within the secret (e.g., public key)
kms_id = "your_kms_key_id"  # AWS KMS Key ID
rsa_padding = "your_padding_type"  # RSA padding scheme (e.g., "PKCS1v15", "OAEP")

try:
    # Perform hybrid encryption
    encrypted_result = encrypt(
        api_response=sensitive_data,
        secret_name=secret_name,
        secret_key=secret_key,
        kms_id=kms_id,
        rsa_padding=rsa_padding
    )

    print("🔐 Encrypted Data:", encrypted_result["encryptedData"])
    print("🔑 Encrypted AES Key:", encrypted_result["encryptedKey"])

except Exception as error:
    print(f"❌ Encryption Error: {error}")
```

### 🔓 Hybrid Decryption:

Decrypt the hybrid-encrypted payload using the corresponding RSA private key and AES-GCM.

```python
from Cryptorix.hybrid import decrypt

# Encrypted inputs
encrypted_data = "your_base64_encoded_encrypted_data"
encrypted_key = "your_base64_encoded_encrypted_key"

# Decryption parameters
secret_name = "your_secret_name"  # AWS Secrets Manager secret name
secret_key = "your_secret_key"  # Key name within the secret (e.g., private key)
kms_id = "your_kms_key_id"  # AWS KMS Key ID
rsa_padding = "your_padding_type"  # RSA padding scheme

try:
    # Perform hybrid decryption
    decrypted_payload = decrypt(
        encrypted_data=encrypted_data,
        encrypted_key=encrypted_key,
        secret_name=secret_name,
        secret_key=secret_key,
        kms_id=kms_id,
        rsa_padding=rsa_padding
    )

    print("✅ Decrypted Response:", decrypted_payload)

except Exception as error:
    print(f"❌ Decryption Error: {error}")
```

### 🔐 KMS Encryption:

Encrypt a plaintext string using AWS Key Management Service (KMS).
The result is a base64-encoded encrypted value.

```python
from Cryptorix.kms import encrypt

# Sensitive information to encrypt
plaintext = "your-sensitive-data"
kms_id = "your_kms_key_id"  # AWS KMS key ID

try:
    # Encrypt using KMS
    encrypted_output = encrypt(plaintext=plaintext, kms_id=kms_id)
    print("🔐 Encrypted Value (Base64):", encrypted_output)
except Exception as error:
    print(f"❌ Encryption Error: {error}")
```

### 🔓 KMS Decryption:

Decrypt a KMS-encrypted base64-encoded string back to its original plaintext using the same KMS key.

```python
from Cryptorix.kms import decrypt

# Encrypted base64 string to decrypt
encrypted_value = "your_base64_encoded_encrypted_value_here"
kms_id = "your_kms_key_id"  # AWS KMS key ID

try:
    # Decrypt using KMS
    decrypted_output = decrypt(encrypted_value=encrypted_value, kms_id=kms_id)
    print("✅ Decrypted Value:", decrypted_output)
except Exception as error:
    print(f"❌ Decryption Error: {error}")
```

### 🔐 Retrieve Decrypted Secret Key:

Fetch and decrypt a specific key from AWS Secrets Manager using AWS KMS.

```python
from Cryptorix.secrets import retrieve_decrypted_secret_key

# Input parameters
secret_name = "your_secret_name"  # Name of the secret in Secrets Manager
secret_key = "your_secret_key"  # Specific key within the secret (e.g., RSA private key)
kms_id = "your_kms_key_id"  # AWS KMS Key ID used for decryption

try:
    # Retrieve and decrypt the secret key
    decrypted_key = retrieve_decrypted_secret_key(
        secret_name=secret_name,
        secret_key=secret_key,
        kms_id=kms_id
    )
    print("🔓 Decrypted RSA Key:", decrypted_key)
except Exception as error:
    print(f"❌ Error retrieving decrypted secret key: {error}")
```

### 📦 Retrieve Secret Key (Unencrypted):

Fetch a specific key from a plain secret in AWS Secrets Manager (no KMS decryption involved).

```python
from Cryptorix.secrets import retrieve_secret_key

# Input parameters
secret_name = "your_secret_name"
secret_key = "your_secret_key"

try:
    # Retrieve the plain secret key
    rsa_key = retrieve_secret_key(secret_name=secret_name, secret_key=secret_key)
    print("🔑 Retrieved Secret Key:", rsa_key)
except Exception as error:
    print(f"❌ Error retrieving secret key: {error}")
```

### 🔍 Retrieve Full Secret:

Fetch the entire secret payload (as a dictionary) from AWS Secrets Manager.

```python
from Cryptorix.secrets import get_secrets

# Input parameter
secret_name = "your_secret_name"

try:
    # Retrieve the full secret object
    secrets = get_secrets(secret_name=secret_name)
    print("📁 Retrieved Secret Data:", secrets)
except Exception as error:
    print(f"❌ Error retrieving secrets: {error}")
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