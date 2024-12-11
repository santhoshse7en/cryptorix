import json
import unittest

from Cryptorix.kms import encrypt, decrypt


class TestHybridEncryption(unittest.TestCase):

    def setUp(self):
        # Set up common parameters for the tests
        self.kms_id = ""
        self.plaintext = "Testing KMS Encryption"
        self.api_response = {"encryption_type": "KMS"}

    def test_kms_plain_text(self):
        encrypted_response = encrypt(
            plaintext=self.plaintext,
            kms_id=self.kms_id
        )
        print("Encrypted Response: ", encrypted_response)

        # Test decryption
        decrypted_response = decrypt(
            encrypted_value=encrypted_response,
            kms_id=self.kms_id
        )

        print("Decrypted Response: ", decrypted_response)

        # Assert that the decrypted response matches the original response
        self.assertEqual(decrypted_response, self.plaintext)

    def test_kms_json_payload(self):
        encrypted_response = encrypt(
            plaintext=json.dumps(self.api_response),
            kms_id=self.kms_id
        )
        print("Encrypted Response: ", encrypted_response)

        # Test decryption
        decrypted_response = decrypt(
            encrypted_value=encrypted_response,
            kms_id=self.kms_id
        )

        print("Decrypted Response: ", decrypted_response)

        # Assert that the decrypted response matches the original response
        self.assertEqual(decrypted_response, self.api_response)


if __name__ == "__main__":
    unittest.main()
