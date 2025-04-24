import unittest
from unittest.mock import patch

from Cryptorix.hybrid import encrypt, decrypt


class TestHybridEncryption(unittest.TestCase):

    def setUp(self):
        # Set up common parameters for the tests
        self.secret_name = "mock_secret_name"  # A valid mock secret name
        self.kms_id = "mock-kms-id"  # A valid mock KMS ID
        self.public_key = "mock_public_key"  # A mock public key
        self.private_key = "mock_private_key"  # A mock private key
        self.api_response = {"encryption_type": "hybrid_encryption"}

    def test_hybrid_encryption_v1(self):
        encrypted_response = encrypt(
            api_response=self.api_response,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id,
            rsa_padding="PKCS1_v1_5"
        )

        # Assert that encryption produces an encrypted value
        self.assertIsNotNone(encrypted_response)
        self.assertIn("encrypted_key", encrypted_response)
        self.assertIn("encrypted_data", encrypted_response)

        # Test decryption
        decrypted_response = decrypt(
            encrypted_key=encrypted_response["encrypted_key"],
            encrypted_data=encrypted_response["encrypted_data"],
            secret_key=self.private_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id,
            rsa_padding="PKCS1_v1_5"
        )

        # Assert that the decrypted response matches the original response
        self.assertEqual(decrypted_response, self.api_response)

    def test_hybrid_encryption_v2(self):
        encrypted_response = encrypt(
            api_response=self.api_response,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id,
            rsa_padding="PKCS1_OAEP"
        )

        # Assert that encryption produces an encrypted value
        self.assertIsNotNone(encrypted_response)
        self.assertIn("encrypted_key", encrypted_response)
        self.assertIn("encrypted_data", encrypted_response)

        # Test decryption
        decrypted_response = decrypt(
            encrypted_key=encrypted_response["encrypted_key"],
            encrypted_data=encrypted_response["encrypted_data"],
            secret_key=self.private_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id,
            rsa_padding="PKCS1_OAEP"
        )

        # Assert that the decrypted response matches the original response
        self.assertEqual(decrypted_response, self.api_response)

    @patch('Cryptorix.hybrid_encryption.decrypt')
    def test_decryption_error(self, mock_decrypt):
        # Simulate decryption failure
        mock_decrypt.side_effect = Exception("Decryption failed")

        with self.assertRaises(Exception) as context:
            decrypt(
                encrypted_key="corrupted_key",
                encrypted_data="corrupted_data",
                secret_key=self.private_key,
                secret_name=self.secret_name,
                kms_id=self.kms_id,
                rsa_padding="PKCS1_v1_5"
            )
        self.assertEqual(str(context.exception), "Decryption failed")


if __name__ == "__main__":
    unittest.main()
