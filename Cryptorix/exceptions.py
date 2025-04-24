from typing import Optional, Dict, Any


class EncryptionError(Exception):
    """Custom exception for encryption and decryption-related errors."""

    def __init__(self,
                 error: str,
                 error_code: Optional[str] = "UNKNOWN_ERROR",
                 function_name: Optional[str] = None,
                 context: Optional[Dict[str, Any]] = None):
        """
        Initialize the EncryptionError instance.

        Args:
            error (str): The error message or description.
            error_code (str, optional): The code representing the type of error
            (defaults to "UNKNOWN_ERROR").
            function_name (str, optional): The name of the function where the error occurred.
            context (dict, optional): Additional context to provide more details about the error
            (e.g., key names or data).
        """
        super().__init__(error)
        self.error_code = error_code
        self.message = error
        self.function_name = function_name
        self.context = context or {}

    def __str__(self) -> str:
        """
        Return a formatted string representation of the error.

        Returns:
            str: Formatted error message.
        """
        context_str = f" | Context: {self.context}" if self.context else ""
        function_str = f"Function: {self.function_name}" if self.function_name else ""
        return f"{self.error_code} - {self.message} ({function_str}){context_str}"
