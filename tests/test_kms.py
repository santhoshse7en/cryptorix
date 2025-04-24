import json
import unittest
from unittest.mock import patch

from Cryptorix.kms import encrypt, decrypt


class TestKMSEncryption(unittest.TestCase):

    def setUp(self):
        # Set up common parameters for the tests
        self.kms_id = "mock-kms-id"  # A valid mock ID for testing
        self.plaintext = "Testing KMS Encryption"
        self.api_response = {"encryption_type": "KMS"}

    def test_kms_plain_text(self):
        encrypted_response = encrypt(
            plaintext=self.plaintext,
            kms_id=self.kms_id
        )

        # Test decryption
        decrypted_response = decrypt(
            encrypted_value=encrypted_response,
            kms_id=self.kms_id
        )

        # Assert that the decrypted response matches the original response
        self.assertEqual(decrypted_response, self.plaintext)

    def test_kms_json_payload(self):
        encrypted_response = encrypt(
            plaintext=json.dumps(self.api_response),
            kms_id=self.kms_id
        )

        # Test decryption
        decrypted_response = decrypt(
            encrypted_value=encrypted_response,
            kms_id=self.kms_id
        )

        # Assert that the decrypted response matches the original response
        self.assertEqual(decrypted_response, self.api_response)

    @patch('Cryptorix.kms.decrypt')
    def test_decryption_error(self, mock_decrypt):
        # Simulate decryption failure
        mock_decrypt.side_effect = Exception("Decryption failed")

        with self.assertRaises(Exception) as context:
            decrypt(encrypted_value="corrupted_data", kms_id=self.kms_id)
        self.assertEqual(str(context.exception), "Decryption failed")


if __name__ == "__main__":
    unittest.main()
