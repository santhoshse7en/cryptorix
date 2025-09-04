# 🔐 Cryptorix

**Cryptorix** is a powerful Python package that makes it easy to securely encrypt and decrypt data
using:

* **AES**, **FERNET**, **JWE**, and **Hybrid Encryption**
* **AWS KMS** and **Secrets Manager** for secure key management

It supports both symmetric (AES) and asymmetric (RSA) encryption, and integrates directly with AWS
services to keep your secrets safe.

## 🧩 Overview

Cryptorix simplifies encryption workflows by offering modular support for:

* AES and FERNET for secure data encryption
* JWE for secure token exchange
* Hybrid Encryption (AES + RSA)
* AWS KMS for encrypting values
* AWS Secrets Manager for retrieving and decrypting secrets

---

## 🚀 Features

### AES

Encrypt and decrypt Python dictionaries with AES encryption.

```python
from Cryptorix.aes import encrypt, decrypt

encrypted = encrypt(data="your_data", aes_key="your_hex_key")
decrypted = decrypt(encrypted_data=encrypted, aes_key="your_hex_key")
```

---

### Fernet

Encrypt and decrypt Python dictionaries with Fernet encryption.

```python
from Cryptorix.fernet import encrypt, decrypt

encrypted = encrypt(data="your_data", key=b"your_key")
decrypted = decrypt(encrypted_data=encrypted, key=b"your_key")
```

---

### JWE

Use RSA + AES-GCM to encrypt and decrypt data in JWE format.

```python
from Cryptorix.jwe import encrypt, decrypt

jwe_token = encrypt(data={}, public_key_pem="your_public_key_pem")
original_data = decrypt(encrypted_data=jwe_token, private_key_pem="your_private_key_pem")
```

---

### Hybrid Encryption

Combines AES for content and RSA for key encryption.

```python
from Cryptorix.hybrid import encrypt, decrypt

result = encrypt(data={}, public_key_pem="your_public_key_pem")
original = decrypt(
    encrypted_data=result["encryptedData"],
    encrypted_key=result["encryptedKey"],
    private_key_pem="your_private_key_pem"
)
```

---

### AWS KMS

Encrypt and decrypt plain strings using AWS Key Management Service.

```python
from Cryptorix.kms import encrypt, decrypt

enc = encrypt(plaintext="hello", kms_key_id="your_kms_key_id")
dec = decrypt(ciphertext_b64=enc)
```

---

### AWS Secrets Manager

Fetch secrets securely from AWS.

```python
from Cryptorix.secrets import get_secret_dict, get_secret_value

all_secrets = get_secret_dict(secret_name="your_secret_name")
plain = get_secret_value(secret_name="your_secret_name", key="your_secret_key")
```

---

## 📦 Installation

Install via pip:

```bash
pip install Cryptorix
```

---

## ✅ AWS Permissions

Ensure the following IAM permissions:

* **KMS**

    * `kms:Encrypt`
    * `kms:Decrypt`
* **Secrets Manager**

    * `secretsmanager:GetSecretValue`

---

## 🧰 Dependencies

* [`boto3`](https://pypi.org/project/boto3/)
* [`cryptography`](https://pypi.org/project/cryptography/)
* [`jwcrypto`](https://pypi.org/project/jwcrypto/)
* [`pycryptodome`](https://pypi.org/project/pycryptodome/)

---

## 📄 License

MIT License

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or pull requests.

---

## 👤 Author

**M Santhosh Kumar**
📧 [santhoshse7en@gmail.com](mailto:santhoshse7en@gmail.com)

---