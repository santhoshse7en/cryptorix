import unittest

from Cryptorix.jwe import encrypt, decrypt


class TestHybridEncryption(unittest.TestCase):

    def setUp(self):
        # Set up common parameters for the tests
        self.secret_name = ""
        self.kms_id = ""
        self.public_key = ""
        self.private_key = ""
        self.api_response = {"encryption_type": "JWE"}

    def test_jwe(self):
        encrypted_response = encrypt(
            api_response=self.api_response,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )
        print("Encrypted Response: ", encrypted_response)

        # Test decryption
        decrypted_response = decrypt(
            jwe_payload=encrypted_response,
            secret_key=self.private_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id
        )

        print("Decrypted Response: ", decrypted_response)

        # Assert that the decrypted response matches the original response
        self.assertEqual(decrypted_response, self.api_response)


if __name__ == "__main__":
    unittest.main()
