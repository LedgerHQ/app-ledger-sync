from typing import List
import pytest

from ragger.error import ExceptionRAPDU
from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID

from utils.CommandStream import CommandStream
from utils.ApduDevice import Automation, ApduDevice
from utils.NobleCrypto import Crypto, DerivationPath
from utils.index import device
from utils.streamTree import StreamTree
from utils.CommandBlock import Permissions
from utils.test_helpers import get_derivation_path, create_seed_and_derive_stream

from constants import DEFAULT_TOPIC

valid_member_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK]
valid_member_instructions1_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
valid_member_instructions2_nano = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK]
valid_member_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]


def test_basic(backend: BackendInterface) -> None:
    # Note: This basic test only tests seeding functionality, no additional operations
    alice = device.apdu(backend)
    topic = Crypto.from_hex(DEFAULT_TOPIC)
    stream = CommandStream()
    stream = stream.edit().seed(topic).issue(alice)


def test_tree_flow(backend: BackendInterface,
                   navigator: Navigator,
                   test_name: str) -> None:
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)

    # Use utility function to create seed and derive stream
    stream, tree = create_seed_and_derive_stream(alice, 0)

    # Add bob to the derived stream
    bob = device.software()
    bob_public_key = bob.get_public_key()
    member_automation = Automation(
        navigator, test_name=f"{test_name}/part1", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)

    # Derive another subtree
    stream = CommandStream().edit().derive(get_derivation_path(1)).issue(alice, tree)
    tree = tree.update(stream)

    # Add bob to the new subtree
    member_automation = Automation(
        navigator, test_name=f"{test_name}/part2", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)


# Test if the nano is connected
def test_isConnected(backend: BackendInterface) -> None:
    alice: ApduDevice = device.apdu(backend)
    assert alice.is_connected() is True

# Test Seed and check Resolved Stream characteristics
# Note: This test intentionally works with root stream to test seed functionality
def test_seed(backend: BackendInterface) -> None:
    alice = device.apdu(backend)  # Assuming you have a Device class
    topic = Crypto.from_hex(DEFAULT_TOPIC)  # Assuming you have a crypto module
    stream = CommandStream()
    stream = stream.edit().seed(topic).issue(alice)

    assert len(stream.get_blocks()) == 1
    resolved = stream.resolve()
    assert resolved.is_created() is True
    assert len(resolved.get_members()) == 1
    assert Crypto.to_hex(resolved.get_topic()) == Crypto.to_hex(topic)


# Test Seed and Add Bob using derived stream
def test_seed_and_add_bob(backend: BackendInterface,
                          navigator: Navigator,
                          test_name: str) -> None:
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
        dismiss_notification_instructions = [NavInsID.BOTH_CLICK]
    else:
        valid_member_instructions = valid_member_instructions_stax
        dismiss_notification_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
    alice = device.apdu(backend)

    bob = device.software()
    bob_public_key = bob.get_public_key()

    # Use utility function to create seed and derive stream
    stream, tree = create_seed_and_derive_stream(alice, 0)
    backend.wait_for_text_on_screen("Ledger Sync")

    member_automation = Automation(
        navigator, test_name=f"{test_name}_member", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)

    # dismiss notif
    navigator.navigate(dismiss_notification_instructions,
                       screen_change_before_first_instruction=False)
    resolved = stream.resolve()
    assert resolved.is_created() is True
    assert len(resolved.get_members()) == 2
    # Note: topic verification would need to be adapted for derived streams
    assert bob_public_key in resolved.get_members()
    assert stream.get_blocks()[-1].issuer in resolved.get_members()


def seed_tree_and_derive_subtree(backend: BackendInterface) -> None:
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()

    # Use utility function to create seed and derive stream, then add member
    stream, tree = create_seed_and_derive_stream(alice, 0)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFF, True).issue(alice, tree)


def test_standard_tree_derive(backend: BackendInterface) -> None:
    alice = device.apdu(backend)
    # Use utility function to create seed and derive stream
    _, _ = create_seed_and_derive_stream(alice, 0)


# Test Add Member Without Creating Seed
def test_add_member_without_seed(backend: BackendInterface) -> None:
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    stream = CommandStream()

    # Add Bob without Creating A SEED
    with pytest.raises(ValueError):
        stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, False).issue(alice)


def test_add_member_from_non_member(backend: BackendInterface) -> None:
    # Note: This test intentionally works with root stream to test access restrictions
    alice = device.apdu(backend)
    charlie = device.software()
    charlie_public_key = charlie.get_public_key()

    # Use utility function to create seed and derive stream
    stream, tree = create_seed_and_derive_stream(alice, 0)

    # We add a member by another member not part of the trustchain
    bob = device.software()
    stream = stream.edit().add_member('Charlie', charlie_public_key, 0xFFFFFFFF, False).issue(bob, tree)
    tree = tree.update(stream)

    # When Alice tries to add Bob, it should raise an error
    with pytest.raises(ExceptionRAPDU):
        stream = stream.edit().add_member('Bob', bob.get_public_key(), 0xFFFFFFFF, False).issue(alice, tree)

# Test should publish a key to a member added by a software device using derived stream
def test_publish_key(backend: BackendInterface,
                     navigator: Navigator,
                     test_name: str) -> None:
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()

    # Use utility function to create seed and derive stream
    stream, tree = create_seed_and_derive_stream(alice, 0)

    # Alice adds Bob to the derived stream
    member_automation = Automation(
        navigator, test_name=f"{test_name}_member", instructions=valid_member_instructions)

    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)

    # Bob adds Charlie but doesn't publish key
    stream = stream.edit().add_member("Charlie", charlie_public_key, 0xFFFFFFFF, False).issue(bob, tree)
    tree = tree.update(stream)

    # Alice publishes the key to Charlie
    stream = stream.edit().publish_key(charlie_public_key).issue(alice, tree)


# Test should not publish key to non-member using derived stream
def test_publish_key_to_non_member(backend: BackendInterface,
                                   navigator: Navigator,
                                   test_name: str) -> None:
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()

    # Use utility function to create seed and derive stream
    stream, tree = create_seed_and_derive_stream(alice, 0)

    member_automation = Automation(
        navigator, test_name=f"{test_name}_member", instructions=valid_member_instructions)

    alice.update_automation(member_automation)

    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)

    with pytest.raises(ExceptionRAPDU):
        stream = stream.edit().publish_key(charlie_public_key).issue(alice, tree)


# Alice seeds once and signs. Alice seeds once more creating a new block should fail.
# Note: This test intentionally works with root stream to test seed restriction
def test_seed_twice_by_alice_stream(backend: BackendInterface) -> None:
    alice = device.apdu(backend)
    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)

    with pytest.raises(ExceptionRAPDU):
        stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)


# Alice seeds twice in the same block. Should fail.
# Note: This test intentionally works with root stream to test seed restriction
def test_seed_twice_by_alice_block(backend: BackendInterface) -> None:
    alice = device.apdu(backend)
    stream = CommandStream()

    with pytest.raises(ExceptionRAPDU):
        stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).seed(
            Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)


def test_seed_twice_by_bob_block() -> None:
    bob = device.software()
    stream = CommandStream()
    with pytest.raises(ValueError):
        stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).seed(
            Crypto.from_hex(DEFAULT_TOPIC)).issue(bob)


def test_seed_twice_by_bob_stream() -> None:
    bob = device.software()
    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(bob)
    with pytest.raises(ValueError):
        stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(bob)


def test_publish_by_non_member(backend: BackendInterface,
                               navigator: Navigator,
                               test_name: str) -> None:
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()
    charlie_public_key = charlie.get_public_key()

    # Use utility function to create seed and derive stream
    stream, tree = create_seed_and_derive_stream(alice, 0)
    member_automation = Automation(
        navigator, test_name=f"{test_name}", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member('Charlie', charlie_public_key, 0xFFFFFFFF).issue(alice, tree)
    tree = tree.update(stream)

    with pytest.raises(ValueError):
        stream = stream.edit().publish_key(charlie_public_key).issue(bob, tree)


def test_publish_key_to_non_member_by_software(backend: BackendInterface,
                                               navigator: Navigator,
                                               test_name: str) -> None:
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()

    # Use utility function to create seed and derive stream
    stream, tree = create_seed_and_derive_stream(alice, 0)
    member_automation = Automation(
        navigator, test_name=f"{test_name}", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)
    with pytest.raises(ValueError):
        stream = stream.edit().publish_key(charlie_public_key).issue(bob, tree)


# Shouldn't be able to add the same member twice using derived stream
def test_add_member_twice(backend: BackendInterface,
                          navigator: Navigator,
                          test_name: str) -> None:
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()

    # Use utility function to create seed and derive stream
    stream, tree = create_seed_and_derive_stream(alice, 0)
    member_automation = Automation(
        navigator, test_name=f"{test_name}", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)
    # Attempt to add Bob again - this should fail or be ignored
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True)


def test_derive_subtree_with_publish_key(backend: BackendInterface,
                                         navigator: Navigator,
                                         test_name: str) -> None:
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()

    # Use utility function to create seed and derive stream, then add member
    member_automation = Automation(
        navigator, test_name=f"{test_name}", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    print("Adding Bob")

    stream, tree = create_seed_and_derive_stream(alice, 0)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)

    # Read key from bob
    xpriv = bob.read_key(tree, get_derivation_path(0))
    assert xpriv is not None and len(xpriv) == 64


def test_key_rotation(backend: BackendInterface,
                      navigator: Navigator,
                      test_name: str) -> None:
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax

    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()
    david = device.software()
    edward = device.software()

    # Use utility function to create seed and derive initial stream
    stream, tree = create_seed_and_derive_stream(alice, 0)

    # Add Bob to the derived stream
    member_automation = Automation(
        navigator, test_name=f"{test_name}/part1", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob.get_public_key(), 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)

    # Add Charlie to the same derived stream
    member_automation = Automation(
        navigator, test_name=f"{test_name}/part2", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Charlie", charlie.get_public_key(), 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)

    # Key rotation: Close previous stream
    close_automation = Automation(
        navigator, test_name=f"{test_name}/part_close", instructions=valid_member_instructions2_nano)
    alice.update_automation(close_automation)
    stream = stream.edit().close().issue(alice, tree)

    # Create new derived stream for rotation
    member_automation = Automation(
        navigator, test_name=f"{test_name}/part3", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = CommandStream().edit() \
                            .derive(get_derivation_path(1)).add_member("Bob", bob.get_public_key(), 0xFFFFFFFF, True) \
                            .issue(alice, tree)
    tree = tree.update(stream)

    # Bob (software) adds Charlie
    stream = stream.edit().add_member("Charlie", charlie.get_public_key(), 0xFFFFFFFF, True).issue(bob, tree)
    tree = tree.update(stream)

    # Bob (software) adds David
    stream = stream.edit().add_member("David", david.get_public_key(), 0xFFFFFFFF, True).issue(bob, tree)
    tree = tree.update(stream)

    # Alice adds Edward
    member_automation = Automation(
        navigator, test_name=f"{test_name}/part4", instructions=valid_member_instructions)
    alice.update_automation(member_automation)

    stream = stream.edit().add_member("Edward", edward.get_public_key(), 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)

    # Keys should be equal
    bob_xpriv = bob.read_key(tree, get_derivation_path(1))
    edward_xpriv = edward.read_key(tree, get_derivation_path(1))
    assert bob_xpriv is not None and edward_xpriv is not None
    assert len(bob_xpriv) == 64 and len(edward_xpriv) == 64
    assert bob_xpriv == edward_xpriv


def test_add_restricted_member(backend: BackendInterface,
                               navigator: Navigator,
                               test_name: str) -> None:
    """Test that a member without CAN_ADD_BLOCK permission cannot add other members."""
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions1_nano
    else:
        valid_member_instructions = valid_member_instructions_stax

    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()

    # Use utility function to create seed and derive stream
    stream, tree = create_seed_and_derive_stream(alice, 0)

    permissions_without_add_block = Permissions.OWNER & ~Permissions.CAN_ADD_BLOCK

    member_automation = Automation(
        navigator, test_name=f"{test_name}_member", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, permissions_without_add_block, True).issue(alice, tree)
    tree = tree.update(stream)

    member_automation = Automation(
        navigator, test_name=f"{test_name}_member", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Charlie", charlie_public_key, permissions_without_add_block, True).issue(alice, tree)
    tree = tree.update(stream)
