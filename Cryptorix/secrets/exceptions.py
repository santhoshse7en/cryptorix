class SecretRetrievalError(Exception):
    """Custom exception for Secret retrieval-related errors."""

    def __init__(self, error, error_code=None, function_name=None, context=None):
        super().__init__(error)
        self.error_code = error_code
        self.message = error
        self.function_name = function_name
        self.context = context

    def __str__(self):
        context_str = f" | Context: {self.context}" if self.context else ""
        return f"{self.error_code} - {self.message} (Function: {self.function_name}){context_str}"
