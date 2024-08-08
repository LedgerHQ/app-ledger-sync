# SECP256k1

import hashlib
import os
from Crypto.Cipher import AES
from bip32 import BIP32  # type: ignore
import secp256k1  # type: ignore
from cffi import FFI  # type: ignore
ffi = FFI()

# BIP32

# OS

# HASHING


# AES

# ECDH


class Crypto:
    # Generates a Private Key and a Public Key from SECP256k1 Elliptic curve
    @staticmethod
    def randomKeyPair():
        privateKeyObj = secp256k1.PrivateKey()
        privateKey = privateKeyObj.private_key
        publicKey = privateKeyObj.pubkey.serialize()

        return {
            'publicKey': publicKey,
            'privateKey': privateKey
        }

    @staticmethod
    def keyPair_from_secret_key(secret):
        private = secp256k1.PrivateKey(secret)
        public = private.pubkey.serialize()
        return {'publicKey': public, 'privateKey': secret}

    @staticmethod
    def derive_private(xpriv: bytes, path: list) -> dict:
        pk = xpriv[:32]
        chain_code = xpriv[32:]

        obj = BIP32(chain_code, pk)
        return {
            'publicKey': obj.get_pubkey_from_path(path),
            'privateKey': obj.get_extended_privkey_from_path(path)[1],
            'chainCode': obj.get_extended_privkey_from_path(path)[0]
        }

    @staticmethod
    def sign(message, keyPair):
        privateKey = secp256k1.PrivateKey(keyPair['privateKey'])
        obj = privateKey.ecdsa_sign(message, raw=True)
        return privateKey.ecdsa_serialize(obj)

    # Takes a hexadecimal string and turns it into a bytes object
    @staticmethod
    def from_hex(hex_str):
        return bytes.fromhex(hex_str)

    # Concatenates two bytearrays
    @staticmethod
    def concat(a: bytearray, b: bytearray) -> bytes:
        c = bytearray(len(a) + len(b))
        c[:len(a)] = a
        c[len(a):] = b
        return bytes(c)

    # Verifies the validity of a signature, message and public key
    @staticmethod
    def verify(message, signature, public_key):
        # Deserialize the public key
        pubkey = secp256k1.PublicKey(bytes(public_key), raw=True)
        # Verify the signature`
        # print('Sig: ' + Crypto.to_hex(signature))
        signatureEcdsa = ffi.new(f"unsigned char[{len(bytes(signature))}]", signature)
        signatureEcdsa = pubkey.ecdsa_deserialize(signatureEcdsa)
        is_valid = pubkey.ecdsa_verify(bytes(message), signatureEcdsa, raw=True)

        return is_valid

    # Creates a 32 byte hash, input must be sequence of bytes, byte array or bytes.
    @staticmethod
    def hash(message):
        sha256_hash = hashlib.sha256(message).digest()
        return sha256_hash

    # Converts a sequence of bytes to a byte array
    @staticmethod
    def to_array(buffer):
        return bytearray(buffer)

    # Converts a bytearray to hex code
    @staticmethod
    def to_hex(byte_array):
        if not isinstance(byte_array, bytearray) and not isinstance(byte_array, bytes):
            return ""
        return "".join(format(byte, '02x') for byte in byte_array)

    @staticmethod
    def to_repr(byte_array: bytearray):
        if not isinstance(byte_array, bytearray) and not isinstance(byte_array, bytes):
            return repr(byte_array)

        return Crypto.to_hex(byte_array)

    # Creates a byte array with (size bytes)
    @staticmethod
    def random_bytes(size):
        return bytes(os.urandom(size))

    # Used to validate and check length for AES encryption
    @staticmethod
    def normalize_key(key):
        if len(key) == 32:
            return key
        raise ValueError(f"Invalid key length for AES-256 (invalid length is {len(key)})")

    # Validate and return the first 16 bytes
    @staticmethod
    def normalize_nonce(nonce):
        if len(nonce) < 16:
            raise ValueError(
                f"Invalid nonce length (must be 128 bits) (invalid length is {len(nonce)})")
        return nonce[:16]

    # Encrypts a piece of data/message using AES CBC 256
    @staticmethod
    def encrypt(secret, nonce, message):
        normalizedSecret = Crypto.normalize_key(secret)
        encryption_cipher = AES.new(normalizedSecret, AES.MODE_GCM, nonce)
        encrypted, tag = encryption_cipher.encrypt_and_digest(message)
        return encrypted + tag

    # Decrypts a cipher text
    @staticmethod
    def decrypt(secret, nonce, cipherText):
        normalizedSecret = Crypto.normalize_key(secret)
        tag = cipherText[-16:]
        encrypted = cipherText[:-16]
        decryption_cipher = AES.new(normalizedSecret, AES.MODE_GCM, nonce)
        return decryption_cipher.decrypt_and_verify(encrypted, tag)

    @staticmethod
    def ecdh(keyPair: dict, publicKey: bytes) -> bytes:
        public = secp256k1.PublicKey(publicKey, raw=True)
        point = public.tweak_mul(keyPair['privateKey'])
        secret = point.serialize(compressed=True)
        return secret[1:]


class DerivationPath:
    def __init__(self):
        pass

    @staticmethod
    def to_index_array(path):
        if isinstance(path, list):
            return path
        if len(path) == 0:
            return []
        if path.startswith("m/"):
            path = path[2:]

        return [int(s[:-1]) + 0x80000000 if s.endswith("'") or s.endswith("h") else int(s) for s in path.split("/")]

    @staticmethod
    def to_string(path):
        if isinstance(path, str):
            return path
        return "m/" + "/".join([(str(s - 0x80000000) + "'" if s >= 0x80000000 else str(s)) for s in path])
