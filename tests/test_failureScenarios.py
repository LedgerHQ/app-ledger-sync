import pytest
from ragger.error import ExceptionRAPDU
from ragger.backend.interface import BackendInterface
from ragger.navigator import NavInsID

from utils.CommandStream import CommandStream
from utils.NobleCrypto import Crypto
from utils.CommandBlock import CommandBlock, commands, sign_command_block
from utils.index import device
from utils.ApduDevice import Device, Automation
from utils.CommandStreamEncoder import CommandStreamEncoder

from pathlib import Path

DEFAULT_TOPIC = "c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a261474192851"

# Basic Signature Flow


def test_basic_signature_flow(backend: BackendInterface):
    sessionKey = Crypto.randomKeyPair()

    block = CommandBlock(
        0,  # Version
        Crypto.random_bytes(32),  # Parent
        bytes([0] * 33),
        [commands.Seed(
            Crypto.from_hex(DEFAULT_TOPIC),
            0,
            Crypto.random_bytes(32),
            bytes([0] * 16),
            bytes([0] * 64),
            bytes([0] * 33),
        )],
        bytes([0] * 0)
    )

    # Initialize flow
    Device.initFlow(backend, sessionKey['publicKey'])

    # ParseBlockHeader
    Device.signBlockHeader(backend, CommandStreamEncoder.encodeBlockHeader(block))

    # Commands
    # Device.parseCommand(backend, CommandStreamEncoder.encodeCommand(block,0))
    Device.signCommand(backend, CommandStreamEncoder.encodeCommand(block, 0))

    # Finalize signature
    Device.finalizeSignature(backend)

# We finalize twice, should fail.


def test_finalize_twice(backend: BackendInterface):
    sessionKey = Crypto.randomKeyPair()

    block = CommandBlock(
        0,  # Version
        Crypto.random_bytes(32),  # Parent
        bytes([0] * 33),
        [commands.Seed(
            Crypto.from_hex(DEFAULT_TOPIC),
            0,
            Crypto.random_bytes(32),
            bytes([0] * 16),
            bytes([0] * 64),
            bytes([0] * 33),
        )],
        bytes([0] * 0)
    )

    # Initialize flow
    Device.initFlow(backend, sessionKey['publicKey'])

    # ParseBlockHeader
    Device.signBlockHeader(backend, CommandStreamEncoder.encodeBlockHeader(block))

    # Commands
    # Device.parseCommand(backend, CommandStreamEncoder.encodeCommand(block,0))
    Device.signCommand(backend, CommandStreamEncoder.encodeCommand(block, 0))

    # Finalize signature
    Device.finalizeSignature(backend)

    with pytest.raises(ExceptionRAPDU):
        Device.finalizeSignature(backend)


def test_sign_header_after_finalize(backend: BackendInterface):
    sessionKey = Crypto.randomKeyPair()

    block = CommandBlock(
        0,  # Version
        Crypto.random_bytes(32),  # Parent
        bytes([0] * 33),
        [commands.Seed(
            Crypto.from_hex(DEFAULT_TOPIC),
            0,
            Crypto.random_bytes(32),
            bytes([0] * 16),
            bytes([0] * 64),
            bytes([0] * 33),
        )],
        bytes([0] * 0)
    )

    # Initialize flow
    Device.initFlow(backend, sessionKey['publicKey'])

    # ParseBlockHeader
    Device.signBlockHeader(backend, CommandStreamEncoder.encodeBlockHeader(block))

    # Commands
    # Device.parseCommand(backend, CommandStreamEncoder.encodeCommand(block,0))
    Device.signCommand(backend, CommandStreamEncoder.encodeCommand(block, 0))

    # Finalize signature
    Device.finalizeSignature(backend)

    with pytest.raises(ExceptionRAPDU):
        Device.signBlockHeader(backend, CommandStreamEncoder.encodeBlockHeader(block))


# Should fail to sign when flow was not initialized
def test_no_init(backend):
    with pytest.raises(ExceptionRAPDU):
        Device.finalizeSignature(backend)


# Should fail to sign a block when bypassing command parsing
def test_bypass_command(backend: BackendInterface):
    sessionKey = Crypto.randomKeyPair()

    block = CommandBlock(
        0,  # Version
        Crypto.random_bytes(32),  # Parent
        bytes([0] * 33),
        [commands.Seed(
            Crypto.from_hex(DEFAULT_TOPIC),
            0,
            Crypto.random_bytes(32),
            bytes([0] * 16),
            bytes([0] * 64),
            bytes([0] * 33),
        )],
        bytes([0] * 0)
    )

    # Initialize flow
    Device.initFlow(backend, sessionKey['publicKey'])

    # ParseBlockHeader
    Device.signBlockHeader(backend, CommandStreamEncoder.encodeBlockHeader(block))

    with pytest.raises(ExceptionRAPDU):
        Device.finalizeSignature(backend)


# Test should fail when bypassing header signingx
def test_bypass_header(backend: BackendInterface):
    sessionKey = Crypto.randomKeyPair()

    block = CommandBlock(
        0,  # Version
        Crypto.random_bytes(32),  # Parent
        bytes([0] * 33),
        [commands.Seed(
            Crypto.from_hex(DEFAULT_TOPIC),
            0,
            Crypto.random_bytes(32),
            bytes([0] * 16),
            bytes([0] * 64),
            bytes([0] * 33),
        )],
        bytes([0] * 0)
    )

    # Initialize flow
    Device.initFlow(backend, sessionKey['publicKey'])

    with pytest.raises(ExceptionRAPDU):
        Device.signCommand(backend, CommandStreamEncoder.encodeCommand(block, 0))


# Test should fail to signblockheader when not initialized flow
def test_bypass_init_header(backend: BackendInterface):
    sessionKey = Crypto.randomKeyPair()

    block = CommandBlock(
        0,  # Version
        Crypto.random_bytes(32),  # Parent
        bytes([0] * 33),
        [commands.Seed(
            Crypto.from_hex(DEFAULT_TOPIC),
            0,
            Crypto.random_bytes(32),
            bytes([0] * 16),
            bytes([0] * 64),
            bytes([0] * 33),
        )],
        bytes([0] * 0)
    )

    with pytest.raises(ExceptionRAPDU):
        Device.signBlockHeader(backend, CommandStreamEncoder.encodeBlockHeader(block))


def test_bypass_one_command(backend):
    sessionKey = Crypto.randomKeyPair()
    block = CommandBlock(
        0,  # Version
        Crypto.random_bytes(32),  # Parent
        bytes([0] * 33),

        # Commands
        [
            commands.Seed(
                Crypto.from_hex(DEFAULT_TOPIC),
                0,
                Crypto.random_bytes(32),
                bytes([0] * 16),
                bytes([0] * 64),
                bytes([0] * 33),
            ),

            commands.AddMember(
                'Bob',
                Crypto.randomKeyPair()['publicKey'],
                0xFFFFFFFF
            )
        ],
        bytes([0]*0)
    )

    Device.initFlow(backend, sessionKey['publicKey'])

    Device.signBlockHeader(backend, CommandStreamEncoder.encodeBlockHeader(block))

    Device.signCommand(backend, CommandStreamEncoder.encodeCommand(block, 0))

    # Device.signCommand(backend, CommandStreamEncoder.encodeCommand(block 1))

    with pytest.raises(ExceptionRAPDU):
        Device.finalizeSignature(backend)


# TEST FOR TOMORROW
# TEST INVALID SIGNATURE IN PREVIOUS BLOCK
def test_false_signature_with_resolve(backend: BackendInterface):
    sessionKey = Crypto.randomKeyPair()

    block = CommandBlock(
        0,  # Version
        Crypto.random_bytes(32),  # Parent
        Crypto.randomKeyPair()["publicKey"],
        [commands.Seed(
            Crypto.from_hex(DEFAULT_TOPIC),
            0,
            Crypto.random_bytes(32),
            bytes([0] * 16),
            bytes([0] * 64),
            bytes([0] * 33),
        )],
        bytes([1, 2, 3])
    )

    stream = CommandStream([block])
    Device.initFlow(backend, sessionKey['publicKey'])
    with pytest.raises(AssertionError):
        resolved = stream.resolve()


def test_false_signature_with_parsing(backend: BackendInterface):
    bob = device.software()
    bob_public_key = bob.get_public_key()
    sessionKey = Crypto.randomKeyPair()

    block = CommandBlock(
        0,  # Version
        Crypto.random_bytes(32),  # Parent
        bob_public_key,
        [commands.Seed(
            Crypto.from_hex(DEFAULT_TOPIC),
            0,
            Crypto.random_bytes(32),
            bytes([0] * 16),
            bytes([0] * 64),
            bytes([0] * 33),
        )],
        bytes([0]*0)
    )

    signedBlock = sign_command_block(block, bob_public_key, bob.key_pair['privateKey'])

    stream = [signedBlock]
    Device.initFlow(backend, sessionKey['publicKey'])
    Device.parse_block_header(backend, CommandStreamEncoder.encodeBlockHeader(stream[0]))
    Device.parseCommand(backend, CommandStreamEncoder.encodeCommand(stream[0], 0))

    with pytest.raises(ExceptionRAPDU):
        Device.parse_signature(backend, stream[0].signature)
