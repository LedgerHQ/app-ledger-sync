import pytest

from ragger.error import ExceptionRAPDU
from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID

from utils.CommandStream import CommandStream
from utils.CommandBlock import Permissions
from utils.NobleCrypto import Crypto, DerivationPath
from utils.CommandBlock import CommandBlock, commands
from utils.index import device
from utils.ApduDevice import Device, Automation
from utils.CommandStreamEncoder import CommandStreamEncoder
from utils.streamTree import StreamTree

from constants import DEFAULT_TOPIC

ROOT_DERIVATION_PATH = "16'/0'"

valid_member_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
valid_member_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]


def get_derivation_path(index: int):
    return DerivationPath.to_index_array(f"{ROOT_DERIVATION_PATH}/{index}'")


def create_seed_and_derive_stream(device_instance, derivation_index: int = 0, topic: bytes = None):
    """
    Utility function to create a root seed stream and derive a new stream from it.
    This prevents adding blocks directly to the root stream and follows the proper flow.

    Args:
        device_instance: The device instance to use for issuing commands
        derivation_index: The index for the derivation path (default: 0)
        topic: The topic bytes to use for seeding (default: DEFAULT_TOPIC)

    Returns:
        tuple: (derived_stream, stream_tree)
    """
    if topic is None:
        topic = Crypto.from_hex(DEFAULT_TOPIC)

    # Create the root seed stream
    root_stream = CommandStream()
    root_stream = root_stream.edit().seed(topic).issue(device_instance)
    tree = StreamTree.from_streams(root_stream)

    # Derive a new stream from the root
    derived_stream = CommandStream()
    derived_stream = derived_stream.edit().derive(get_derivation_path(derivation_index)).issue(device_instance, tree)
    tree = tree.update(derived_stream)

    return derived_stream, tree


# Basic Signature Flow
def test_basic_signature_flow(backend: BackendInterface) -> None:

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
    Device.signCommand(backend, CommandStreamEncoder.encodeCommand(block, 0))

    # Finalize signature
    Device.finalizeSignature(backend)


# We finalize twice, should fail.
def test_finalize_twice(backend: BackendInterface) -> None:

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
    Device.signCommand(backend, CommandStreamEncoder.encodeCommand(block, 0))

    # Finalize signature
    Device.finalizeSignature(backend)

    with pytest.raises(ExceptionRAPDU):
        Device.finalizeSignature(backend)


def test_sign_header_after_finalize(backend: BackendInterface) -> None:

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
    Device.signCommand(backend, CommandStreamEncoder.encodeCommand(block, 0))

    # Finalize signature
    Device.finalizeSignature(backend)

    with pytest.raises(ExceptionRAPDU):
        Device.signBlockHeader(backend, CommandStreamEncoder.encodeBlockHeader(block))


# Should fail to sign when flow was not initialized
def test_no_init(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU):
        Device.finalizeSignature(backend)


# Should fail to sign a block when bypassing command parsing
def test_bypass_command(backend: BackendInterface) -> None:
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
def test_bypass_header(backend: BackendInterface) -> None:
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
def test_bypass_init_header(backend: BackendInterface) -> None:
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


def test_bypass_one_command(backend: BackendInterface) -> None:

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

    with pytest.raises(ExceptionRAPDU):
        Device.finalizeSignature(backend)


# TEST INVALID SIGNATURE IN PREVIOUS BLOCK
def test_false_signature_with_resolve(backend: BackendInterface) -> None:
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
        stream.resolve()


def test_add_member_with_zero_permissions(backend: BackendInterface) -> None:
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()

    stream, tree = create_seed_and_derive_stream(alice, 0)

    # Alice adds Bob with zero permissions
    with pytest.raises((ExceptionRAPDU)):
        stream = stream.edit().add_member("Bob", bob_public_key, 0, True).issue(alice, tree)


def test_add_member_without_can_add_block_permission(backend: BackendInterface,
                                                     navigator: Navigator,
                                                     test_name: str) -> None:
    """Test that a member without CAN_ADD_BLOCK permission should not be able to add blocks,
        and APDU device should refuse to sign subsequent blocks."""
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax

    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()

    # Use utility function to create seed and derive stream
    stream, tree = create_seed_and_derive_stream(alice, 0)

    # Alice adds Bob with permissions that don't include CAN_ADD_BLOCK
    permissions = Permissions.OWNER & ~(Permissions.CAN_ADD_BLOCK)

    member_automation = Automation(
        navigator, test_name=f"{test_name}", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, permissions, True).issue(alice, tree)
    tree = tree.update(stream)

    # Bob adds a block
    charlie = device.software()
    charlie_public_key = charlie.get_public_key()
    # Bob issues this in software - this will create a tampered stream
    tampered_stream = stream.edit().add_member("Charlie", charlie_public_key, Permissions.OWNER, True).issue(bob, tree)
    tampered_tree = tree.update(tampered_stream)

    # Alice tries to sign another operation on the tampered stream - APDU device should reject
    dany = device.software()
    dany_public_key = dany.get_public_key()
    with pytest.raises(ExceptionRAPDU):
        tampered_stream.edit().add_member("Dany", dany_public_key, Permissions.OWNER, True).issue(alice, tampered_tree)
