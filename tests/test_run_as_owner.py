from typing import List
import pytest

from ragger.error import ExceptionRAPDU
from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID

from utils.CommandStream import CommandStream
from utils.ApduDevice import Automation, ApduDevice
from utils.NobleCrypto import Crypto, DerivationPath
from utils.index import device
from utils.streamTree import StreamTree

from constants import DEFAULT_TOPIC

ROOT_DERIVATION_PATH = "16'/0'"

valid_member_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK]
valid_member_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]


def get_derivation_path(index: int) -> List[int]:
    return DerivationPath.to_index_array(f"{ROOT_DERIVATION_PATH}/{index}'")


def test_basic(backend: BackendInterface) -> None:
    alice = device.apdu(backend)
    topic = Crypto.from_hex(DEFAULT_TOPIC)
    stream = CommandStream()
    stream = stream.edit().seed(topic).issue(alice)


def test_tree_flow(firmware: Firmware,
                   backend: BackendInterface,
                   navigator: Navigator,
                   test_name: str) -> None:
    if firmware.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)

    topic = Crypto.from_hex(DEFAULT_TOPIC)
    stream = CommandStream()

    # Create the root
    stream = stream.edit().seed(topic).issue(alice)
    tree = StreamTree.from_streams(stream)

    # Create the subtree
    stream = CommandStream().edit().derive(get_derivation_path(0)).issue(alice, tree)
    tree = tree.update(stream)

    # Add bob to the subtree
    bob = device.software()
    bob_public_key = bob.get_public_key()
    member_automation = Automation(
        navigator, test_name=f"{test_name}/part1", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)

    # Derive a new subtree
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


# Test Seed and Add Bob
def test_seed_and_add_bob(firmware: Firmware,
                          backend: BackendInterface,
                          navigator: Navigator,
                          test_name: str) -> None:
    if firmware.is_nano:
        valid_member_instructions = valid_member_instructions_nano
        dismiss_notification_instructions = [NavInsID.BOTH_CLICK]
    else:
        valid_member_instructions = valid_member_instructions_stax
        dismiss_notification_instructions = [NavInsID.USE_CASE_STATUS_DISMISS]
    alice = device.apdu(backend)

    bob = device.software()
    bob_public_key = bob.get_public_key()
    topic = Crypto.from_hex(DEFAULT_TOPIC)
    stream = CommandStream()

    stream = stream.edit().seed(topic).issue(alice)
    backend.wait_for_text_on_screen("Ledger Sync")

    member_automation = Automation(
        navigator, test_name=f"{test_name}_member", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)

    # dismiss notif
    navigator.navigate(dismiss_notification_instructions,
                       screen_change_before_first_instruction=False)
    resolved = stream.resolve()
    assert resolved.is_created() is True
    assert len(resolved.get_members()) == 2
    assert Crypto.to_hex(resolved.get_topic()) == Crypto.to_hex(topic)
    assert bob_public_key in resolved.get_members()
    assert stream.get_blocks()[0].issuer in resolved.get_members()


def seed_tree_and_derive_subtree(backend: BackendInterface) -> None:
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    topic = Crypto.to_hex(DEFAULT_TOPIC)
    stream = CommandStream()
    stream = stream.edit().seed(topic).add_member("Bob", bob_public_key, 0xFFFFFFF, True).issue(alice)


def test_standard_tree_derive(backend: BackendInterface) -> None:
    alice = device.apdu(backend)
    topic = Crypto.from_hex(DEFAULT_TOPIC)
    stream = CommandStream()
    stream = stream.edit().seed(topic).issue(alice)

    tree = StreamTree.from_streams(stream)
    stream = stream.edit().derive(get_derivation_path(0)).issue(alice, tree)
    tree.update(stream)


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
    alice = device.apdu(backend)
    charlie = device.software()
    charlie_public_key = charlie.get_public_key()
    topic = Crypto.from_hex(DEFAULT_TOPIC)

    stream = CommandStream()
    stream = stream.edit().seed(topic).issue(alice)

    # We add a member by an another member not part of the trustchain
    bob = device.software()
    stream = stream.edit().add_member('Charlie', charlie_public_key, 0xFFFFFFFF, False).issue(bob)


# Test should publish a key to a member added by a software device
def test_publish_key(firmware: Firmware,
                     backend: BackendInterface,
                     navigator: Navigator,
                     test_name: str) -> None:
    if firmware.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()

    stream = CommandStream()

    # Alice creates the stream and adds Bob
    stream = stream.edit().seed((Crypto.from_hex(DEFAULT_TOPIC))).issue(alice)
    member_automation = Automation(
        navigator, test_name=f"{test_name}_member", instructions=valid_member_instructions)

    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)

    # Bob adds Charlie but doesn't publish key
    stream = stream.edit().add_member("Charlie", charlie_public_key, 0xFFFFFFFF, False).issue(bob)

    # Alice publishes the key to Charlie
    stream = stream.edit().publish_key(charlie_public_key).issue(alice)


# Test should not publish key to non-member
def test_publish_key_to_non_member(firmware: Firmware,
                                   backend: BackendInterface,
                                   navigator: Navigator,
                                   test_name: str) -> None:
    if firmware.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()

    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)

    member_automation = Automation(
        navigator, test_name=f"{test_name}_member", instructions=valid_member_instructions)

    alice.update_automation(member_automation)

    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)

    with pytest.raises(ExceptionRAPDU):
        stream = stream.edit().publish_key(charlie_public_key).issue(alice)


# Alice seeds once and signs. Alice seeds once more creating a new block should fail.
def test_seed_twice_by_alice_stream(backend: BackendInterface) -> None:
    alice = device.apdu(backend)
    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)

    with pytest.raises(ExceptionRAPDU):
        stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)


# Alice seeds twice in the same block. Should fail.
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


def test_publish_by_non_member(firmware: Firmware,
                               backend: BackendInterface,
                               navigator: Navigator,
                               test_name: str) -> None:
    if firmware.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()
    charlie_public_key = charlie.get_public_key()

    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)
    member_automation = Automation(
        navigator, test_name=f"{test_name}", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member('Charlie', charlie_public_key, 0xFFFFFFFF).issue(alice)

    with pytest.raises(ValueError):
        stream = stream.edit().publish_key(charlie_public_key).issue(bob)


def test_publish_key_to_non_member_by_software(firmware: Firmware,
                                               backend: BackendInterface,
                                               navigator: Navigator,
                                               test_name: str) -> None:
    if firmware.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()

    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)
    member_automation = Automation(
        navigator, test_name=f"{test_name}", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)
    with pytest.raises(ValueError):
        stream = stream.edit().publish_key(charlie_public_key).issue(bob)


# Shouldn't be able to add the same member twice
def test_add_member_twice(firmware: Firmware,
                          backend: BackendInterface,
                          navigator: Navigator,
                          test_name: str) -> None:
    if firmware.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)
    member_automation = Automation(
        navigator, test_name=f"{test_name}", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True)


def test_derive_subtree_with_publish_key(firmware: Firmware,
                                         backend: BackendInterface,
                                         navigator: Navigator,
                                         test_name: str) -> None:
    if firmware.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)
    member_automation = Automation(
        navigator, test_name=f"{test_name}", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    print("Adding Bob")
    # Derive and publish to bob
    tree = StreamTree.from_streams(stream)
    new_stream = CommandStream()
    new_stream = new_stream.edit().derive(get_derivation_path(0)) \
        .add_member("Bob",bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(new_stream)

    # Read key from bob
    xpriv = bob.read_key(tree, get_derivation_path(0))
    assert xpriv is not None and len(xpriv) == 64


def test_key_rotation(firmware: Firmware,
                      backend: BackendInterface,
                      navigator: Navigator,
                      test_name: str) -> None:
    if firmware.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax

    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()
    david = device.software()
    edward = device.software()

    # Seed
    stream = CommandStream().edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)
    tree = StreamTree.from_streams(stream)
    # Create a branch
    member_automation = Automation(
        navigator, test_name=f"{test_name}/part1", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = CommandStream().edit() \
                            .derive(get_derivation_path(0)).add_member("Bob", bob.get_public_key(), 0xFFFFFFFF, True) \
                            .issue(alice, tree)
    tree = tree.update(stream)

    # Add Charlie
    member_automation = Automation(
        navigator, test_name=f"{test_name}/part2", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = CommandStream().edit() \
                            .derive(get_derivation_path(0)).add_member("Charlie", charlie.get_public_key(), 0xFFFFFFFF, True) \
                            .issue(alice, tree)
    tree = tree.update(stream)

    # Key rotation: Close previous stream
    close_automation = Automation(
        navigator, test_name=f"{test_name}/part_close", instructions=valid_member_instructions)
    alice.update_automation(close_automation)
    stream = stream.edit().close().issue(alice, tree)

    # Create new branch
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
