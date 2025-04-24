import unittest
from unittest.mock import patch

from Cryptorix.jwe import encrypt, decrypt


class TestJWEEncryption(unittest.TestCase):
    def setUp(self):
        """Set up common parameters for the tests."""
        self.secret_name = "your_secrets"  # Mock secret name
        self.kms_id = "your_kms_id"  # Mock KMS ID
        self.public_key = "your_public_key"  # Mock public key
        self.private_key = "your_private_key"  # Mock private key
        self.api_response = {"encryption_type": "JWE"}

    def test_jwe(self):
        """Test successful JWE encryption and decryption."""
        encrypted_response = encrypt(
            api_response=self.api_response,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )

        # Assert that encryption produces an encrypted value
        self.assertIsNotNone(encrypted_response)

        # Decrypt and verify the result
        decrypted_response = decrypt(
            jwe_payload=encrypted_response,
            secret_key=self.private_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )

        # Assert that the decrypted response matches the original response
        self.assertEqual(decrypted_response, self.api_response)

    @patch('Cryptorix.jwe.decrypt')
    def test_decryption_error(self, mock_decrypt):
        """Test decryption failure."""
        error = ("DECRYPTION_FAILED - Invalid format {InvalidJWEData('Unknown Data "
                 "Verification Failure')} (Function: decrypt) | Context: {'secret_name': "
                 "'cavec_test_suite_secrets', 'kms_id': 'effe95b1-f8c6-48c5-8fa3-ea135d5eafb6', "
                 "'jwe_payload': 'corrupted_data...'}")

        mock_decrypt.side_effect = Exception(error)

        with self.assertRaises(Exception) as context:
            decrypt(
                jwe_payload="corrupted_data",
                secret_key=self.private_key,
                secret_name=self.secret_name,
                kms_id=self.kms_id
            )
        self.assertEqual(str(context.exception), error)

    def test_empty_api_response(self):
        """Test encryption and decryption with an empty API response."""
        empty_response = {}
        encrypted_response = encrypt(
            api_response=empty_response,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )
        self.assertIsNotNone(encrypted_response)

        decrypted_response = decrypt(
            jwe_payload=encrypted_response,
            secret_key=self.private_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )
        self.assertEqual(decrypted_response, empty_response)

    def test_invalid_secret_key(self):
        """Test decryption with an invalid secret key."""
        invalid_private_key = "invalid_private_key"  # Invalid private key
        encrypted_response = encrypt(
            api_response=self.api_response,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )

        with self.assertRaises(Exception) as context:
            decrypt(
                jwe_payload=encrypted_response,
                secret_key=invalid_private_key,
                secret_name=self.secret_name,
                kms_id=self.kms_id
            )

        self.assertIn("DECRYPTION_FAILED", str(context.exception))

    def test_corrupted_jwe_payload(self):
        """Test decryption failure with corrupted JWE payload."""
        corrupted_jwe_payload = "corrupted_jwe_data"

        with self.assertRaises(Exception) as context:
            decrypt(
                jwe_payload=corrupted_jwe_payload,
                secret_key=self.private_key,
                secret_name=self.secret_name,
                kms_id=self.kms_id
            )

        self.assertIn("DECRYPTION_FAILED", str(context.exception))

    def test_invalid_jwe_format(self):
        """Test decryption failure with an invalid JWE format."""
        invalid_jwe_format = "non_base64_jwe_payload"

        with self.assertRaises(Exception) as context:
            decrypt(
                jwe_payload=invalid_jwe_format,
                secret_key=self.private_key,
                secret_name=self.secret_name,
                kms_id=self.kms_id
            )

        self.assertIn("DECRYPTION_FAILED", str(context.exception))

    def test_large_data_encryption_decryption(self):
        """Test encryption and decryption with a large payload."""
        large_data = {"data": "x" * 10 ** 6}  # 1MB of data
        encrypted_response = encrypt(
            api_response=large_data,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )
        self.assertIsNotNone(encrypted_response)

        decrypted_response = decrypt(
            jwe_payload=encrypted_response,
            secret_key=self.private_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )
        self.assertEqual(decrypted_response, large_data)

    def test_missing_secret_name_or_kms_id(self):
        """Test error handling when secret_name or kms_id is missing."""
        # Test missing secret_name during encryption
        with self.assertRaises(Exception) as context:
            encrypt(
                api_response=self.api_response,
                secret_key=self.public_key,
                secret_name="",  # Missing secret_name
                kms_id=self.kms_id
            )

        self.assertIn("ENCRYPTION_FAILED", str(context.exception))

        # Test missing kms_id during encryption
        with self.assertRaises(Exception) as context:
            encrypt(
                api_response=self.api_response,
                secret_key=self.public_key,
                secret_name=self.secret_name,
                kms_id=""  # Missing kms_id
            )

        self.assertIn("ENCRYPTION_FAILED", str(context.exception))

        # Now we check decryption with missing secret_name or kms_id after encryption fails
        encrypted_response = encrypt(
            api_response=self.api_response,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )

        # Test missing secret_name during decryption
        with self.assertRaises(Exception) as context:
            decrypt(
                jwe_payload=encrypted_response,
                secret_key=self.private_key,
                secret_name="",  # Missing secret_name
                kms_id=self.kms_id
            )

        self.assertIn("DECRYPTION_FAILED", str(context.exception))

        # Test missing kms_id during decryption
        with self.assertRaises(Exception) as context:
            decrypt(
                jwe_payload=encrypted_response,
                secret_key=self.private_key,
                secret_name=self.secret_name,
                kms_id=""  # Missing kms_id
            )

        self.assertIn("DECRYPTION_FAILED", str(context.exception))

    def test_repeated_encryption_decryption(self):
        """Test repeated encryption and decryption on the same data."""
        encrypted_response = encrypt(
            api_response=self.api_response,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )
        decrypted_response = decrypt(
            jwe_payload=encrypted_response,
            secret_key=self.private_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )
        self.assertEqual(decrypted_response, self.api_response)

        # Repeat the process to ensure consistency
        encrypted_response_again = encrypt(
            api_response=self.api_response,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )
        decrypted_response_again = decrypt(
            jwe_payload=encrypted_response_again,
            secret_key=self.private_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )
        self.assertEqual(decrypted_response_again, self.api_response)


if __name__ == "__main__":
    unittest.main()
