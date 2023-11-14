# SECP256k1

from ecdsa import ecdh, curves, ecdsa
from Crypto.Util.Padding import pad, unpad
from .hashing import NoHash
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from hashlib import md5
import hashlib
import os
from bip32 import BIP32
import binascii
import tinyec.ec as ecc
from secp256k1 import PublicKey, PrivateKey
import secp256k1
from cffi import FFI
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
        privateKeyObj = PrivateKey()
        privateKey = privateKeyObj.private_key
        publicKey = privateKeyObj.pubkey.serialize()

        return {
            'publicKey': publicKey,
            'privateKey': privateKey
        }

    @staticmethod
    def keyPair_from_secret_key(secret):
        private = PrivateKey(secret)
        public = private.pubkey.serialize()
        return {'publicKey': public, 'privateKey': secret}

    @staticmethod
    def derive_private(xpriv: bytes, path: list) -> dict:
        pk = xpriv[:32]
        chain_code = xpriv[32:]

        object = BIP32(chain_code, pk)
        return {
            'publicKey': object.get_pubkey_from_path(path),
            'privateKey': object.get_extended_privkey_from_path(path)[1],
            'chainCode': object.get_extended_privkey_from_path(path)[0]
        }

    @staticmethod
    def pad(message):
        # ISO9797M2 implementation
        padlength = AES.block_size - (len(message) % AES.block_size)
        if padlength == AES.block_size:
            return message

        padding = bytearray(padlength)
        padding[0] = 0x80

        for i in range(1, padlength):
            padding[i] = 1

        return Crypto.concat(message, padding)

    @staticmethod
    def unpad(message):
        # ISO9797M2 implementation
        if message[-1] != 0x00 and message[-1] != 0x80:
            return message

        for i in range(len(message) - 1, -1, -1):
            if message[i] == 0x80:
                return message[:i]
            if message[i] != 0x00:
                return message
        raise ValueError('Invalid padding')

    @staticmethod
    def sign(message, keyPair):
        privateKey = PrivateKey(keyPair['privateKey'])
        object = privateKey.ecdsa_sign(message, raw=True)
        return privateKey.ecdsa_serialize(object)

    # Takes a hexadecimal string and turns it into a bytes object
    @staticmethod
    def from_hex(hex_str):
        return bytes.fromhex(hex_str)

    # Concatenates two bytearrays
    @staticmethod
    def concat(a: bytearray, b: bytearray) -> bytearray:
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
        signatureEcdsa = ffi.new('unsigned char[%d]' % len(bytes(signature)), signature)
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
        if type(byte_array) != bytearray and type(byte_array) != bytes:
            return ""
        return "".join(format(byte, '02x') for byte in byte_array)

    @staticmethod
    def to_repr(byte_array: bytearray):
        if type(byte_array) != bytearray and type(byte_array) != bytes:
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
        encryption_cipher = AES.new(normalizedSecret, AES.MODE_CBC, nonce)
        return encryption_cipher.encrypt(Crypto.pad(message))

    # Decrypts a cipher text

    @staticmethod
    def decrypt(secret, nonce, cipherText):
        normalizedSecret = Crypto.normalize_key(secret)
        decryption_cipher = AES.new(normalizedSecret, AES.MODE_CBC, nonce)
        return Crypto.unpad(decryption_cipher.decrypt(cipherText))

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


'''
def ecdh(keyPair, publicKey): 
            group = ecc.SubGroup(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                                            0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8), 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,0x1)
            curve = ecc.Curve(0x0, 0x7,group, 'secp256k1')
        
            keyPair1 = ecc.Keypair(curve, int.from_bytes(keyPair['privateKey'],byteorder='big', signed = False),int.from_bytes(keyPair['publicKey'],byteorder='big', signed = False))
            keyPair2 = ecc.Keypair(curve, None, int.from_bytes(publicKey,byteorder='big', signed = False))

        
            objECDH = ecc.ECDH(keyPair1)
            secret = objECDH.get_secret(keyPair2)
            #secret = secret.to_bytes(65,'big')
            return type(secret)

'''

print(Crypto.to_hex((Crypto.ecdh({'privateKey': Crypto.from_hex('7a78d422ef9dd3a16579d5a71ed00c874fab0b45e31ae40c36bbb219ff6bdd79')}, Crypto.from_hex(
    '03258b047d404b5e8419f5f9221e02d5f836aff34e839e7627bfc10e70b07f0775')))))
# 8903c057d0909b03c0bb0dc6c18202573bc726c8ab8058e16b41850a261048b6  2322f5d008d3e5ff69e40859f11e27b45ef0fd2cb051dd84a574038792309cb1
