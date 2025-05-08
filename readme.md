[![PyPI Version](https://img.shields.io/pypi/v/Cryptorix.svg?style=flat-square)](https://pypi.org/project/Cryptorix)
[![License](https://img.shields.io/pypi/l/Cryptorix.svg?style=flat-square)](https://pypi.python.org/pypi/Cryptorix)
[![Downloads](https://pepy.tech/badge/Cryptorix/month)](https://pepy.tech/project/Cryptorix)

# 🔒 Cryptorix

**Cryptorix** is a powerful Python package designed to offer robust encryption and decryption solutions using cutting-edge technologies like JSON Web Encryption (JWE), Hybrid Encryption, AWS KMS, and AWS Secrets Manager. 🛡️

It combines both symmetric (AES) and asymmetric (RSA) encryption techniques to ensure the highest levels of **confidentiality** and **integrity** for your data. 🔐

With seamless integration to AWS KMS and Secrets Manager, Cryptorix enables secure management of encryption keys, giving you peace of mind knowing your sensitive information is always protected. ☁️💼

Key Features:

* 🧑‍💻 **Symmetric (AES)** & **Asymmetric (RSA)** encryption
* 🔑 **AWS KMS** integration for key management
* 🔒 **AWS Secrets Manager** support for storing secrets securely
* 🔐 Strong **data protection** and **privacy** mechanisms

Stay safe and keep your data secure with Cryptorix! 💡

## 📚 Table of Contents

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

## 🌐 Overview 

**Cryptorix** is a powerful Python package that helps you encrypt and decrypt data securely using industry-standard encryption algorithms. It focuses on AES for data protection, JWE for secure token exchanges, Hybrid Encryption for high-level data security, and AWS services (KMS and Secrets Manager) for managing encryption keys.

With **Cryptorix**, you can easily ensure data confidentiality and integrity, and integrate seamlessly with AWS services for encryption at rest and in transit. 🔐💼

## 🔧 Modules

### 🔑 AES (Advanced Encryption Standard) Module

This module enables secure encryption and decryption of data using the AES (Advanced Encryption Standard) algorithm.

**Functions:**

* `encrypt(api_response, secret_name, secret_key, kms_id)`: Encrypts a dictionary (`api_response`) using the provided AES key and metadata (`secret_name`, `secret_key`, `kms_id`). 🔒
* `decrypt(jwe_payload, secret_name, secret_key, kms_id)`: Decrypts an AES-encrypted payload (`jwe_payload`) back into its original dictionary format. 🔓

### 🌍 JWE (JSON Web Encryption) Module

This module facilitates secure data encryption and decryption using the JWE standard, which combines RSA for key encryption and AES-GCM for content encryption.

**Functions:**

* `encrypt(api_response, secret_name, secret_key, kms_id)`: Encrypts a dictionary (`api_response`) into a JWE token using RSA encryption to protect the AES key and AES-GCM to encrypt the content. 🔏
* `decrypt(jwe_payload, secret_name, secret_key, kms_id)`: Decrypts a JWE token (`jwe_payload`) back into its original dictionary form using RSA and AES. 🔓

### 🔐 Hybrid Encryption Module

This module implements hybrid encryption, combining AES for encrypting data and RSA for encrypting the AES session key. The encrypted data is Base64-encoded for secure transmission.

**Functions:**

* `encrypt_data(api_response, secret_name, secret_key, kms_id, rsa_padding)`: Encrypts the provided data (`api_response`) using hybrid encryption (AES for data, RSA for session key), then Base64-encodes the encrypted result. 🛡️
* `decrypt_data(encrypted_data, encrypted_key, secret_name, secret_key, kms_id, rsa_padding)`: Decrypts the Base64-encoded encrypted data using RSA and AES to restore the original data. 🔑

### ☁️ KMS (Key Management System) Module

This module integrates with AWS Key Management Service (KMS) to securely encrypt and decrypt data, leveraging AWS's managed encryption keys.

**Functions:**

* `encrypt(plaintext, kms_id)`: Encrypts a plaintext string (`plaintext`) using AWS KMS and returns the encrypted value as a Base64-encoded string. 🔐
* `decrypt(encrypted_value, kms_id)`: Decrypts a KMS-encrypted, Base64-encoded string (`encrypted_value`) using the specified KMS key (`kms_id`). 🔓

### 🗝️ Secrets Manager Module

This module interacts with AWS Secrets Manager to securely retrieve and decrypt sensitive information like secrets and credentials.

**Functions:**

* `retrieve_decrypted_secret_key(secret_name, secret_key, kms_id)`: Retrieves and decrypts a secret key from AWS Secrets Manager using AWS KMS. 🔐
* `retrieve_secret_key(secret_name, secret_key)`: Retrieves a secret key from AWS Secrets Manager without decrypting it. 🛡️
* `get_secrets(ciphertext, kms_id)`: Retrieves and decrypts a specific secret from AWS Secrets Manager using the provided KMS key (`kms_id`). 🔑

## 🚀 Installation

To install the **Cryptorix** package, simply use **pip**:

```bash
pip install Cryptorix
```

Get started with secure encryption in no time! 🔐💻


## ✨ Usage

Here is a basic example of how to use the **Cryptorix** package:

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

### 🔐 JWE Encryption:

Encrypts a dictionary payload using AES-GCM for content encryption and RSA to encrypt the AES key. Key materials are securely retrieved via AWS KMS and Secrets Manager.

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

Decrypts the JWE token back into its original dictionary form using the corresponding RSA private key.

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

Encrypt sensitive data using hybrid encryption: AES-GCM for content encryption and RSA (via AWS KMS and Secrets Manager) for encrypting the AES key.

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

Encrypt a plaintext string using AWS Key Management Service (KMS). The result is a base64-encoded encrypted value.

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

### 🚨 **Exceptions** in Cryptorix

Cryptorix defines custom exceptions to handle specific errors during encryption, decryption, and secret retrieval operations:

* **🔐 HybridEncryptionError**: Raised when hybrid encryption or decryption fails.
* **🔑 JWEError**: Raised during failures in JWE encryption or decryption.
* **🔓 KMSDecryptionError**: Raised if decryption via AWS KMS fails.
* **🔒 KMSEncryptionError**: Raised if encryption via AWS KMS fails.
* **🔐 SecretRetrievalError**: Raised if secrets cannot be retrieved or decrypted from AWS Secrets Manager.

These exceptions help track and handle errors efficiently during encryption/decryption tasks.

---

### ⚙️ **AWS Permissions**

Make sure your AWS IAM role or user has the following permissions for proper functionality:

* **KMS Permissions**:

  * `kms:Encrypt` 🔐
  * `kms:Decrypt` 🔓

* **Secrets Manager Permissions**:

  * `secretsmanager:GetSecretValue` 🔑

These permissions ensure you can encrypt, decrypt, and securely manage secrets using AWS services.

### 📦 **Dependencies**

Cryptorix requires the following libraries for its functionality:

* **[`jwcrypto`](https://pypi.org/project/jwcrypto/)**: Implementation of JOSE Web standards for secure token handling.
* **[`pycryptodome`](https://pypi.org/project/pycryptodome/)**: A powerful cryptographic library for Python.
* **[`boto3`](https://pypi.org/project/boto3/)**: AWS SDK for Python, essential for integrating with AWS services like KMS and Secrets Manager.

---

### 📄 **License**

This project is licensed under the **MIT License**.

---

### 💡 **Contributing**

Contributions are encouraged! You can submit issues or pull requests to improve the package. For major changes, please initiate a discussion first.

---

### 🖋️ **Authors**

* **M Santhosh Kumar**
  Initial work
  Email: [santhoshse7en@gmail.com](mailto:santhoshse7en@gmail.com)
