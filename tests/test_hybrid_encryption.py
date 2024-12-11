import unittest

from Cryptorix.hybrid_encryption import encrypt, decrypt


class TestHybridEncryption(unittest.TestCase):

    def setUp(self):
        # Set up common parameters for the tests
        self.secret_name = ""
        self.kms_id = ""
        self.public_key = ""
        self.private_key = ""
        self.api_response = {"encryption_type": "hybrid_encryption"}

    def test_hybrid_encryption_v1(self):
        encrypted_response = encrypt(
            api_response=self.api_response,
            secret_key=self.public_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id,
            rsa_padding="PKCS1_v1_5"
        )
        print("Encrypted Response: ", encrypted_response)

        # Test decryption
        decrypted_response = decrypt(
            encrypted_key=encrypted_response["encrypted_key"],
            encrypted_data=encrypted_response["encrypted_data"],
            secret_key=self.private_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id,
            rsa_padding="PKCS1_v1_5"
        )

        print("Decrypted Response: ", decrypted_response)

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
        print("Encrypted Response: ", encrypted_response)

        # Test decryption
        decrypted_response = decrypt(
            encrypted_key=encrypted_response["encrypted_key"],
            encrypted_data=encrypted_response["encrypted_data"],
            secret_key=self.private_key,
            secret_name=self.secret_name,
            kms_id=self.kms_id,
            rsa_padding="PKCS1_OAEP"
        )

        print("Decrypted Response: ", decrypted_response)

        # Assert that the decrypted response matches the original response
        self.assertEqual(decrypted_response, self.api_response)


if __name__ == "__main__":
    unittest.main()
