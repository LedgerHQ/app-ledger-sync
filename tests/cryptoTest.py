from NobleCrypto import Crypto
import unittest


class TestCommandStream(unittest.TestCase):
    def test_encrypt_decrypt(self):
        # Test case 1: Check that an encrypted message is the same as the decrypted message
        message = b'Hello World'
        key = Crypto.random_bytes(32)
        nonce = Crypto.random_bytes(16)

        encryptObj = Crypto()
        decryptObj = Crypto()

        encrypted = encryptObj.encrypt(key, nonce, message)
        decrypted = decryptObj.decrypt(key, nonce, encrypted)
        self.assertEqual(decrypted, message)
