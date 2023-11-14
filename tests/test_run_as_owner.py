import pytest
from pathlib import Path

from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID, NavIns, Navigator
from ragger.backend.interface import BackendInterface

import utils.CommandStreamResolver
from utils.CommandStream import CommandStream
from utils.ApduDevice import Device, Automation
from utils.NobleCrypto import Crypto, DerivationPath
from utils.Device import createDevice
from utils.index import device
from utils.streamTree import StreamTree

ROOT_DERIVATION_PATH = "16'/0'"
DEFAULT_TOPIC = "c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a261474192851"


def get_derivation_path(index):
    return DerivationPath.to_index_array(f'{ROOT_DERIVATION_PATH}/{index}\'')


def bytes_equal(a, b):
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def test_basic(backend):
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    topic = Crypto.from_hex(DEFAULT_TOPIC)
    stream = CommandStream()
    stream = stream.edit().seed(topic).issue(alice)


'''
def test_tree_derive_subtree(backend):
     alice = device.apdu(backend)
     bob = device.software()
     bob_public_key = bob.get_public_key()
     topic = Crypto.from_hex(DEFAULT_TOPIC)
     stream = CommandStream()
     stream = stream.edit().seed(topic).add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)

     #We added Bob to the root stream, to be able to perform the derivation from both the device and the software
     #to check the same data are derived.

     tree = StreamTree.from_streams(stream)
     stream = CommandStream()
     stream = stream.edit().derive(get_derivation_path(0)).issue(alice, tree)
     stream = stream.edit().seed(topic).add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice,tree)
     tree = tree.update(stream)

     resolve = stream.resolve()
     derivation = tree.get_child(get_derivation_path(0))
     root = tree.get_root()

     assert derivation != None
     assert root != None
     assert bytes_equal(derivation.blocks[0].parent, root.get_root_hash()) == True
'''


def test_tree_flow(backend):
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()
    david = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key
    david_public_key = david.get_public_key()

    topic = Crypto.from_hex(DEFAULT_TOPIC)
    stream = CommandStream()

    # Create the root
    stream = stream.edit().seed(topic).issue(alice)
    tree = StreamTree.from_streams(stream)

    # Create the subtree
    stream = CommandStream().edit().derive(get_derivation_path(0)).issue(alice, tree)
    tree = tree.update(stream)

    # Add bob and charlie to the subtree
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)

    # Close the subtree
    # stream = stream.edit().close().issue(alice, tree)
    # tree = tree.update(stream)

    # Derive a new subtree
    stream = CommandStream().edit().derive(get_derivation_path(1)).issue(alice, tree)
    tree = tree.update(stream)

    # Add bob to the new subtree
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    tree = tree.update(stream)

    # Bob adds charlie to the new subtree
    # stream = stream.edit().add_member("Charlie", charlie_public_key, 0xFFFFFFFF, True).issue(bob, tree)
    # tree = tree.update(stream)

    # Add david to the new subtree
   # stream = stream.edit().add_member("David", david_public_key, 0xFFFFFFFF, True).issue(alice, tree)
    # tree = tree.update(stream)


# Test if the nano is connected
def test_isConnected(backend):
    alice = device.apdu(backend)
    assert alice.is_connected() is True

# TEST RESOLVE FUNCTION
# Test Seed and check Resolved Stream characteristics


def test_seed(backend):
    alice = device.apdu(backend)  # Assuming you have a Device class
    topic = Crypto.from_hex(DEFAULT_TOPIC)  # Assuming you have a crypto module
    stream = CommandStream()
    stream = stream.edit().seed(topic).issue(alice)

    assert len(stream._blocks) == 1
    resolved = stream.resolve()
    assert resolved.is_created() is True
    assert len(resolved.get_members()) == 1
    assert Crypto.to_hex(resolved.get_topic()) == Crypto.to_hex(topic)

# Test Seed and Add Bob


def test_seed_and_add_bob(backend):
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    topic = Crypto.from_hex(DEFAULT_TOPIC)
    stream = CommandStream()
    stream = stream.edit().seed(topic).issue(alice)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)

    resolved = stream.resolve()
    assert resolved.is_created() is True
    assert len(resolved.get_members()) == 2
    assert Crypto.to_hex(resolved.get_topic()) == Crypto.to_hex(topic)
    assert (bob_public_key) in resolved.get_members()
    assert (stream._blocks[0].issuer) in resolved.get_members()

# Should seed a new tree, and derive a subtree and add a member in the subtree


def seed_tree_and_derive_subtree(backend):
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    topic = Crypto.to_hex(DEFAULT_TOPIC)
    stream = CommandStream()
    stream = stream.edit().seed(topic).add_member("Bob", bob_public_key, 0xFFFFFFF, True).issue(alice)

    tree = StreamTree.from_streams(stream)


def test_standard_tree_derive(backend):
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    topic = Crypto.from_hex(DEFAULT_TOPIC)
    stream = CommandStream()
    stream = stream.edit().seed(topic).issue(alice)

    tree = StreamTree.from_streams(stream)
    stream = stream.edit().derive(get_derivation_path(0)).issue(alice, tree)
    tree.update(stream)


# Test Add Member Without Creating Seed
def test_add_member_without_seed(backend):
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    stream = CommandStream()

    # Add Bob without Creating A SEED
    with pytest.raises(ValueError):
        stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, False).issue(alice)


def test_add_member_from_non_member(backend):
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()
    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()
    topic = Crypto.from_hex(DEFAULT_TOPIC)

    stream = CommandStream()
    stream = stream.edit().seed(topic).issue(alice)

    # We add a member by an another member not part of the trustchain
    stream = stream.edit().add_member('Charlie', charlie_public_key, 0xFFFFFFFF, False).issue(bob)


# Test should publish a key to a member added by a software device
def test_publish_key(backend):
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()

    stream = CommandStream()

    # Alice creates the stream and adds Bob
    stream = stream.edit().seed((Crypto.from_hex(DEFAULT_TOPIC))).issue(alice)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)

    # Bob adds Charlie but doesn't publish key
    stream = stream.edit().add_member("Charlie", charlie_public_key, 0xFFFFFFFF, False).issue(bob)

    # Alice publishes the key to Charlie
    stream = stream.edit().publish_key(charlie_public_key).issue(alice)

# Test should not publish key to non-member


def test_publish_key_to_non_member(backend):
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()

    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).add_member(
        "Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)

    with pytest.raises(ExceptionRAPDU):
        stream = stream.edit().publish_key(charlie_public_key).issue(alice)

    with pytest.raises(ExceptionRAPDU):
        stream = stream.edit().publish_key(charlie_public_key).issue(alice)


def test_seed_twice_by_alice_stream(backend):
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)

    with pytest.raises(ExceptionRAPDU):
        stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)

# Alice seeds twice in the same block. Should fail.


def test_seed_twice_by_alice_block(backend):
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    stream = CommandStream()

    with pytest.raises(ExceptionRAPDU):
        stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).seed(
            Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)


def test_seed_twice_by_bob_block(backend):
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    stream = CommandStream()
    with pytest.raises(ValueError):
        stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).seed(
            Crypto.from_hex(DEFAULT_TOPIC)).issue(bob)


def test_seed_twice_by_bob_stream(backend):
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(bob)
    with pytest.raises(ValueError):
        stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(bob)


def test_publish_by_non_member(backend):
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    charlie_public_key = charlie.get_public_key()
    bob_public_key = bob.get_public_key()

    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)
    stream = stream.edit().add_member('Charlie', charlie_public_key, 0xFFFFFFFF).issue(alice)

    with pytest.raises(ValueError):
        stream = stream.edit().publish_key(charlie_public_key).issue(bob)


def test_publish_key_to_non_member_by_software(backend):
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    bob_public_key = bob.get_public_key()
    charlie_public_key = charlie.get_public_key()

    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).add_member(
        "Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)
    with pytest.raises(ValueError):
        stream = stream.edit().publish_key(charlie_public_key).issue(bob)


# Shouldn't be able to add the same member twice

def test_add_member_twice(backend):
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    stream = CommandStream()
    stream = stream.edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).add_member(
        "Bob", bob_public_key, 0xFFFFFFFF, True).issue(alice)
    stream = stream.edit().add_member("Bob", bob_public_key, 0xFFFFFFFF, True)
