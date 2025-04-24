import unittest
from unittest.mock import patch

from Cryptorix.aes import encrypt, decrypt


class TestHybridEncryption(unittest.TestCase):
    def setUp(self):
        """Set up common parameters for the tests."""
        # A mock AES key (32 bytes for AES-256)
        self.aes_key = "your_aes_key"
        # A mock API response
        self.api_response = {"encryption_type": "AES"}

    def test_aes_encryption_decryption(self):
        """Test AES encryption and decryption."""
        encrypted_response = encrypt(api_response=self.api_response, aes_key=self.aes_key)
        self.assertIsNotNone(encrypted_response)
        decrypted_response = decrypt(encrypted_data=encrypted_response, aes_key=self.aes_key)
        self.assertEqual(decrypted_response, self.api_response)

    @patch('Cryptorix.aes.decrypt')
    def test_decryption_error(self, mock_decrypt):
        """Test decryption error handling."""

        error_message = ("DECRYPTION_ERROR - Decryption failed: Only base64 data is allowed "
                         "(Function: decrypt) | Context: {'aes_key': '***MASKED***', "
                         "'encrypted_data': 'corrupted_data...'}")

        mock_decrypt.side_effect = Exception(error_message)

        with self.assertRaises(Exception) as context:
            decrypt(encrypted_data="corrupted_data", aes_key=self.aes_key)

        self.assertEqual(
            str(context.exception),
            error_message
        )

    def test_empty_api_response(self):
        """Test encryption and decryption with an empty API response."""
        empty_response = {}
        encrypted_response = encrypt(api_response=empty_response, aes_key=self.aes_key)
        self.assertIsNotNone(encrypted_response)
        decrypted_response = decrypt(encrypted_data=encrypted_response, aes_key=self.aes_key)
        self.assertEqual(decrypted_response, empty_response)

    def test_invalid_aes_key(self):
        """Test decryption with an invalid AES key."""
        invalid_aes_key = "invalid_aes_key_12345"  # Invalid key (not 32 bytes)
        encrypted_response = encrypt(api_response=self.api_response, aes_key=self.aes_key)

        with self.assertRaises(Exception) as context:
            decrypt(encrypted_data=encrypted_response, aes_key=invalid_aes_key)

        self.assertIn("DECRYPTION_ERROR", str(context.exception))

    def test_corrupted_encrypted_data(self):
        """Test decryption failure with corrupted encrypted data."""
        corrupted_data = "corrupted_data"

        with self.assertRaises(Exception) as context:
            decrypt(encrypted_data=corrupted_data, aes_key=self.aes_key)

        self.assertIn("DECRYPTION_ERROR", str(context.exception))

    def test_invalid_encrypted_data_format(self):
        """Test invalid encrypted data format (non-base64)."""
        invalid_format_data = "non_base64_encrypted_data"

        with self.assertRaises(Exception) as context:
            decrypt(encrypted_data=invalid_format_data, aes_key=self.aes_key)

        self.assertIn("DECRYPTION_ERROR", str(context.exception))

    def test_large_data_encryption_decryption(self):
        """Test encryption and decryption with a large payload."""
        large_data = {"data": "x" * 10 ** 6}  # 1MB of data
        encrypted_response = encrypt(api_response=large_data, aes_key=self.aes_key)
        self.assertIsNotNone(encrypted_response)
        decrypted_response = decrypt(encrypted_data=encrypted_response, aes_key=self.aes_key)
        self.assertEqual(decrypted_response, large_data)


if __name__ == "__main__":
    unittest.main()
