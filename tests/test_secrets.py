import unittest

from Cryptorix.secrets import retrieve_secret_key, retrieve_decrypted_secret_key, get_secrets


class TestHybridEncryption(unittest.TestCase):

    def setUp(self):
        # Set up common parameters for the tests
        self.kms_id = "your_kms_id"
        self.secret_name = "your_secret_name"
        self.public_key = "your_public_key"
        self.private_key = "your_private_key"

        self.secrets_value = ""
        self.decrypted_secrets = ""
        self.secrets = {}

    def test_retrieve_secret_key(self):
        secrets_value = retrieve_secret_key(
            secret_name=self.secret_name,
            secret_key=self.public_key
        )
        print("Secrets Value: ", secrets_value)

        # Assert that the decrypted response matches the original response
        self.assertEqual(secrets_value, self.secrets_value)

    def test_retrieve_decrypted_secret_key(self):
        decrypted_secrets = retrieve_decrypted_secret_key(
            secret_name=self.secret_name,
            secret_key=self.public_key,
            kms_id=self.kms_id
        )
        print("Decrypted Secrets: ", decrypted_secrets)

        # Assert that the decrypted response matches the original response
        self.assertEqual(decrypted_secrets, self.decrypted_secrets)

    def test_get_secrets(self):
        secrets = get_secrets(
            secret_name=self.secret_name,
            secret_key=self.public_key
        )
        print("Secrets: ", secrets)

        # Assert that the decrypted response matches the original response
        self.assertEqual(secrets, self.secrets)


if __name__ == "__main__":
    unittest.main()
