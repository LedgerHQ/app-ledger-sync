
from CommandStreamDecoder import TLV as TLVD, CommandStreamDecoder
from CommandStreamEncoder import TLV as TLVE, CommandStreamEncoder
from CommandBlock import CommandBlock, commands, create_command_block, Permissions, sign_command_block
# from Crypto import Crypto
import unittest
import random
import binascii


class TestCommandStream(unittest.TestCase):
    # Test case 1: Encode and decode a byte
    def test_encode_decode_byte(self):
        byte = 32
        buffer = bytearray()
        buffer = TLVE.pushByte(buffer, byte)
        decoded = TLVD.readVarInt(TLVD.read_tlv(buffer, 0))
        self.assertEqual(decoded['value'], byte)

    # Test case 2: Encode and decode an Int32
    def test_encode_decode_int32(self):
        varint = 0xDEADBEEF
        buffer = bytearray()
        buffer = TLVE.pushInt32(buffer, varint)
        decoded = TLVD.readVarInt(TLVD.read_tlv(buffer, 0))
        self.assertEqual(decoded['value'], varint)

    # Test case 3: Encode and decode a string
    def test_encode_decode_string(self):
        string = "Hello World"
        buffer = bytearray()
        buffer = TLVE.pushString(buffer, string)
        decoded = TLVD.read_string(TLVD.read_tlv(buffer, 0))
        self.assertEqual(decoded['value'], string)

    # Test case 4: Encode and decode a hash

    def test_encode_decode_hash(self):
        hash_value = bytearray([i for i in range(32)])
        buffer = bytearray()
        buffer = TLVE.pushHash(buffer, hash_value)
        decoded = TLVD.read_hash(TLVD.read_tlv(buffer, 0))
        self.assertEqual(decoded['value'], hash_value)

    # Test case 5: Encode and decode bytes

    def test_encode_decode_bytes(self):
        bytes_value = bytearray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        buffer = bytearray()
        buffer = TLVE.pushBytes(buffer, bytes_value)
        decoded = TLVD.read_bytes(TLVD.read_tlv(buffer, 0))
        self.assertEqual(decoded['value'], bytes_value)

    # Test case 6: Encode and decode a signature

    def test_encode_decode_signature(self):
        alice = (bytearray([i for i in range(33)]), bytearray([i for i in range(32)]))
        block = CommandBlock(1, bytearray([i for i in range(33)]),
                             alice[0], [], bytearray([i for i in range(64)]))

        buffer = bytearray()
        buffer = TLVE.pushSignature(buffer, block.signature)
        decoded = TLVD.read_signature(TLVD.read_tlv(buffer, 0))
        self.assertEqual(decoded['value'], block.signature)

    # Test case 7: Encode and decode a public key

    def test_encode_decode_public_key(self):
        alicePub = bytearray([i for i in range(33)])
        buffer = bytearray()
        buffer = TLVE.pushPublicKey(buffer, alicePub)
        decoded = TLVD.read_public_key(TLVD.read_tlv(buffer, 0))
        self.assertEqual(decoded['value'], alicePub)

    # Test Case 8: encode and decode a stream. Encoding/Decoding should not alter the stream
    # Only Test still not working, probably an issue with encoder and decoder

    def test_encode_decode_stream(self):
        alice = (bytearray([i for i in range(33)]), bytearray([i for i in range(32)]))
        groupPk = (bytearray([i for i in range(33)]), bytearray([i for i in range(32)]))
        groupChainCode = bytearray([i for i in range(32)])
        xpriv = bytearray(64)
        initializationVector = bytearray([i for i in range(16)])
        xpriv[:32] = groupPk[1]
        xpriv[32:] = groupChainCode
        ephemeralPk = (bytearray([i for i in range(33)]), bytearray([i for i in range(32)]))

        # block1
        block1 = create_command_block(alice[0], [commands.Seed(
            bytearray([i for i in range(16)]), 0, groupPk[0], initializationVector, xpriv, ephemeralPk[0])])
        block1.signature = bytearray([i for i in range(70)])

        block2 = create_command_block(alice[0],
                                      [commands.AddMember('Alice', alice[0], Permissions.OWNER), commands.PublishKey(initializationVector, xpriv, bytearray([random.randint(1, 100) for i in range(32)]), bytearray([random.randint(1, 100) for i in range(32)]))])
        block2.signature = bytearray([i for i in range(70)])

        stream = [block1, block2]
        encoded = CommandStreamEncoder.encode(stream)
        decoded = CommandStreamDecoder.decode(encoded)

        self.assertEqual(stream, decoded)
