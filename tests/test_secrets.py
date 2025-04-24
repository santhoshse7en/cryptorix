import unittest
from unittest.mock import patch

from Cryptorix.secrets import retrieve_secret_key, retrieve_decrypted_secret_key, get_secrets


class TestSecrets(unittest.TestCase):

    def setUp(self):
        # Set up common parameters for the tests
        self.secret_name = "your_secrets"
        self.public_key = "your_public_key"
        self.kms_id = "your_kms_id"

        # Set expected values for assertions
        self.secrets_value = "mock_secret_value"
        self.decrypted_secrets = "mock_decrypted_secret_value"
        self.secrets = {"secret_name": self.secret_name, "secret_value": self.secrets_value}

    @patch('Cryptorix.secrets.retrieve_secret_key')
    def test_retrieve_secret_key(self, mock_retrieve_secret_key):
        # Mock the response for the retrieve_secret_key function
        mock_retrieve_secret_key.return_value = self.secrets_value

        # Call the function with test parameters
        secrets_value = retrieve_secret_key(
            secret_name=self.secret_name,
            secret_key=self.public_key
        )

        # Assert that the returned value matches the expected value
        self.assertEqual(secrets_value, self.secrets_value)

    @patch('Cryptorix.secrets.retrieve_decrypted_secret_key')
    def test_retrieve_decrypted_secret_key(self, mock_retrieve_decrypted_secret_key):
        # Mock the response for the retrieve_decrypted_secret_key function
        mock_retrieve_decrypted_secret_key.return_value = self.decrypted_secrets

        # Call the function with test parameters
        decrypted_secrets = retrieve_decrypted_secret_key(
            secret_name=self.secret_name,
            secret_key=self.public_key,
            kms_id=self.kms_id
        )

        # Assert that the decrypted secret matches the expected value
        self.assertEqual(decrypted_secrets, self.decrypted_secrets)

    @patch('Cryptorix.secrets.get_secrets')
    def test_get_secrets(self, mock_get_secrets):
        # Mock the response for the get_secrets function
        mock_get_secrets.return_value = self.secrets

        # Call the function with test parameters
        secrets = get_secrets(
            secret_name=self.secret_name
        )

        # Assert that the returned secrets match the expected value
        self.assertEqual(secrets, self.secrets)


if __name__ == "__main__":
    unittest.main()
