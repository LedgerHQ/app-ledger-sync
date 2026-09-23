"""Regression tests for the key the device uses on a stream it did not create.

When the device walks down to a subtree created by another member, the secret it decrypted on
the way belongs to the parent stream, not to the subtree. It must not stay usable there: the
subtree's own key only arrives in a PUBLISH_KEY addressed to the device, and is accepted only
when it reproduces the group key announced by the DERIVE command.
"""

import pytest
from constants import DEFAULT_TOPIC
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID
from utils.ApduDevice import Automation
from utils.CommandBlock import CommandType, Permissions, sign_command_block
from utils.CommandStream import CommandStream
from utils.index import device
from utils.NobleCrypto import Crypto
from utils.streamTree import StreamTree
from utils.test_helpers import get_ledger_sync_path

valid_member_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK]
valid_member_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]

SW_BAD_STATE = 0xB007
SW_STREAM_PARSER_INVALID_FORMAT = 0xB00A


def _owner_instructions(backend: BackendInterface) -> list:
    return valid_member_instructions_nano if backend.device.is_nano else valid_member_instructions_stax


def _device_public_key(alice) -> bytes:
    """Read the device member key off a throwaway stream it signs for itself.

    GET_SEED_ID answers an attestation challenge, not a plain key request, so the member key
    the trustchain uses is only exposed as the issuer of a block the device signed.
    """
    probe = CommandStream().edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(alice)
    return probe.get_blocks()[-1].issuer


def _stream_created_by_bob(alice_public_key, bob, share_key_with_alice: bool):
    """Bob creates the root and the 0'/16'/0' subtree, then registers Alice on the subtree."""
    root = CommandStream().edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(bob)
    tree = StreamTree.from_streams(root)

    derived = CommandStream().edit().derive(get_ledger_sync_path(0)).issue(bob, tree)
    tree = tree.update(derived)

    derived = derived.edit().add_member("Alice", alice_public_key, Permissions.OWNER, share_key_with_alice).issue(bob, tree)
    tree = tree.update(derived)

    return derived, tree


def test_joined_subtree_publishes_its_own_key(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """The key the device republishes on a joined subtree is the subtree key, not its parent."""
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    stream, tree = _stream_created_by_bob(_device_public_key(alice), bob, share_key_with_alice=True)

    automation = Automation(navigator, test_name=test_name, instructions=_owner_instructions(backend))
    alice.update_automation(automation)
    stream = stream.edit().add_member("Charlie", charlie.get_public_key(), Permissions.OWNER, True).issue(alice, tree)
    tree = tree.update(stream)

    subtree_xpriv = bob.derive_key(tree, get_ledger_sync_path(0))["xpriv"]
    root_xpriv = bob.read_key(tree, [])

    assert charlie.read_key(tree, get_ledger_sync_path(0)) == subtree_xpriv
    assert charlie.read_key(tree, get_ledger_sync_path(0)) != root_xpriv


def test_joined_subtree_without_published_key_cannot_publish(
    backend: BackendInterface, navigator: Navigator, test_name: str
) -> None:
    """Without that publication the device holds no key for the subtree and must refuse.

    Before the fix the parent secret was still loaded and got published in its place.
    """
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    stream, tree = _stream_created_by_bob(_device_public_key(alice), bob, share_key_with_alice=False)

    automation = Automation(navigator, test_name=test_name, instructions=_owner_instructions(backend))
    alice.update_automation(automation)
    with pytest.raises(ExceptionRAPDU) as error:
        stream.edit().add_member("Charlie", charlie.get_public_key(), Permissions.OWNER, True).issue(alice, tree)
    assert error.value.status == SW_BAD_STATE


def test_joined_subtree_rejects_a_key_that_is_not_the_group_key(backend: BackendInterface) -> None:
    """A publication to the device is only the subtree key if it reproduces the group key.

    The command is not authenticated when it is parsed, so without that check a host could
    hand the device any key and have it signed as the subtree secret.
    """
    alice = device.apdu(backend)
    bob = device.software()

    stream, tree = _stream_created_by_bob(_device_public_key(alice), bob, share_key_with_alice=True)

    # Replace the published subtree key with an unrelated one, and re-sign the block so only
    # the key binding can reject it
    block = stream.get_blocks()[-1]
    publication = next(c for c in block.commands if c.get_type() == CommandType.PublishKey)
    foreign = bob.generateSharedKey()
    encrypted = bob.encrypt_shared_key(foreign, publication.recipient)
    publication.encrypted_xpriv = encrypted["encryptedXpriv"]
    publication.initialization_vector = encrypted["initializationVector"]
    publication.ephemeral_public_key = encrypted["ephemeralPublicKey"]
    block.signature = bytearray()
    sign_command_block(block, bob.key_pair["privateKey"])

    with pytest.raises(ExceptionRAPDU) as error:
        stream.edit().publish_key(bob.get_public_key()).issue(alice, tree)
    assert error.value.status == SW_STREAM_PARSER_INVALID_FORMAT
