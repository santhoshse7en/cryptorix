# exceptions.py

class CryptorixError(Exception):
    """Base exception for all cryptographic errors."""
    pass


class EncryptionError(CryptorixError):
    """Raised when encryption fails."""
    pass


class DecryptionError(CryptorixError):
    """Raised when decryption fails."""
    pass


class UnsupportedAlgorithmError(CryptorixError):
    """Raised when the algorithm is invalid or unsupported."""
    pass


class KeyFormatError(CryptorixError):
    """Raised when the key is invalid or unsupported."""
    pass


class KMSClientError(CryptorixError):
    """Raised when KMS integration fails."""
    pass


class SecretManagerError(CryptorixError):
    """Raised when accessing the secrets manager fails."""
    pass
