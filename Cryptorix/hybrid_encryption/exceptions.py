class HybridEncryptionError(Exception):
    """Custom exception for HybridEncryption-related errors."""

    def __init__(self, error, error_code=None, function_name=None, context=None):
        super().__init__(error)
        self.error_code = error_code
        self.error = error
        self.function_name = function_name
        self.context = context

    def __str__(self):
        context_str = f" | Context: {self.context}" if self.context else ""
        return f"{self.error_code} - {self.error} (Function: {self.function_name}){context_str}"
