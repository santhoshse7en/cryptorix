# 🔐 Cryptorix

**Cryptorix** is a batteries-included Python toolkit for symmetric and asymmetric cryptography plus AWS-native key management. It bundles a consistent interface for AES, Fernet, JWE, and RSA-based hybrid encryption, together with helpers for AWS Key Management Service (KMS) and Secrets Manager.

---

## 🧭 At a Glance

- **Symmetric encryption** – AES-GCM with key helpers, Fernet with built-in HMAC
- **Asymmetric & token workflows** – RSA + AES hybrid payloads, JWE compact tokens
- **AWS integrations** – Simple wrappers around KMS `encrypt`/`decrypt` and Secrets Manager retrieval
- **Typed error surface** – All helpers raise `CryptorixError` subclasses for predictable handling

---

## 📦 Installation

```bash
pip install Cryptorix
```

> ℹ️ Ensure `boto3`, `cryptography`, `jwcrypto`, and `pycryptodome` are available (installed automatically when using pip).

---

## ⚙️ Quick Start

```python
from Cryptorix.aes import generate_key_hex, encrypt as aes_encrypt, decrypt as aes_decrypt

key = generate_key_hex()  # 256-bit AES key
ciphertext = aes_encrypt({"message": "hello"}, aes_key=key)
plain = aes_decrypt(ciphertext, aes_key=key)  # {'message': 'hello'}
```

```python
from Cryptorix.fernet import generate_key, encrypt as f_encrypt, decrypt as f_decrypt

fernet_key = generate_key()
token = f_encrypt("apples", key=fernet_key)
f_decrypt(token, key=fernet_key)  # 'apples'
```

---

## 🧩 Module Reference

### AES (`Cryptorix.aes`)

- AES-GCM encryption for dict or str payloads
- Accepts keys as 16/24/32 byte strings **or** 32/48/64 hex characters
- Helper utilities: `generate_key_hex()` (64-char hex) and `generate_key_str()` (32-char ASCII)

```python
from Cryptorix.aes import encrypt, decrypt, generate_key_hex

key = generate_key_hex()
ciphertext = encrypt(data={"user": 42}, aes_key=key)
decrypt(ciphertext, aes_key=key)  # {'user': 42}
```

### Fernet (`Cryptorix.fernet`)

- Wraps `cryptography.Fernet` with dict support (auto JSON encoding)
- Generates base64-encoded 32-byte keys

```python
from Cryptorix.fernet import generate_key, encrypt, decrypt

key = generate_key()
token = encrypt({"status": "ok"}, key=key)
decrypt(token, key=key)  # '{"status": "ok"}'
```

### JWE (`Cryptorix.jwe`)

- Produces and validates compact JWE tokens using `RSA-OAEP-256` + `A256GCM`
- Operates strictly on dict payloads

```python
from Cryptorix.jwe import encrypt, decrypt

token = encrypt(data={"scopes": ["read"]}, public_key_pem=rsa_public_pem)
decrypt(token, private_key_pem=rsa_private_pem)  # {'scopes': ['read']}
```

### Hybrid Encryption (`Cryptorix.hybrid`)

- Encrypts dict payloads with a random AES session key and protects that key with RSA
- Supports `PKCS1_OAEP` (default, AES-GCM) and `PKCS1_v1_5` (AES-CBC)
- Returns a dict with `encrypted_data` and `encrypted_key`

```python
from Cryptorix.hybrid import encrypt, decrypt

bundle = encrypt(data={"id": 1}, public_key_pem=rsa_public_pem)
decrypt(
    encrypted_data=bundle["encrypted_data"],
    encrypted_key=bundle["encrypted_key"],
    private_key_pem=rsa_private_pem,
)
```

### AWS KMS (`Cryptorix.kms`)

- Thin wrappers around `boto3.client("kms")`
- `encrypt` returns base64 ciphertext; `decrypt` returns plain text or parsed JSON dict
- Uses `AWS_DEFAULT_REGION` (defaults to `ap-south-1`)

```python
from Cryptorix.kms import encrypt, decrypt

ciphertext = encrypt("top-secret", kms_key_id="arn:aws:kms:...")
decrypt(ciphertext)  # 'top-secret'
```

### AWS Secrets Manager (`Cryptorix.secrets`)

- Fetch full secrets or single keys
- Raises `SecretManagerError` on missing values or AWS failures
- Respects `AWS_DEFAULT_REGION`

```python
from Cryptorix.secrets import get_secret_dict, get_secret_value

db_creds = get_secret_dict("my/db/credentials")
password = get_secret_value("my/db/credentials", key="password")
```

---

## 🔐 Error Handling

All helpers raise `CryptorixError` or one of its specialized subclasses (`EncryptionError`, `DecryptionError`, `KeyFormatError`, `SecretManagerError`, etc.). Catch these to handle failures without leaking service-specific exceptions.

```python
from Cryptorix.aes import encrypt
from Cryptorix.exceptions import CryptorixError

try:
    encrypt("data", aes_key="bad-key")
except CryptorixError as exc:
    # log / recover
    print(f"Encryption failed: {exc}")
```

---

## ✅ AWS Permissions Checklist

- `kms:Encrypt`
- `kms:Decrypt`
- `secretsmanager:GetSecretValue`

Make sure you have standard AWS credentials configured (environment variables, shared config/credentials file, or IAM role).

---

## 📄 License

MIT License

---

## 🤝 Contributing

Issues and pull requests are welcome! Please include reproduction steps or failing tests when reporting bugs.

---

## 👤 Author

**M Santhosh Kumar**  
[santhoshse7en@gmail.com](mailto:santhoshse7en@gmail.com)

---
