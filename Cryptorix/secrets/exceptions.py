class SecretRetrievalError(Exception):
    """Custom exception for Secret retrieval-related errors."""

    def __init__(self, message, error_code=None, function_name=None):
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.function_name = function_name

    def __str__(self):
        return f"{self.error_code} - {self.message} (Function: {self.function_name})"


class KMSDecryptionError(Exception):
    """Custom exception for KMS decryption-related errors."""

    def __init__(self, message, error_code=None, function_name=None):
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.function_name = function_name

    def __str__(self):
        return f"{self.error_code} - {self.message} (Function: {self.function_name})"
