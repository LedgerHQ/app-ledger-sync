"""AppID scope regression tests.

The AppID selects which member operations the device will review and sign. It belongs to one
derived stream and must never be carried into another stream or another signing session: a
root Seed stream holds the parent xpriv of every application subtree, so a member operation
performed there under a borrowed policy would publish that parent key.
"""

import pytest
from constants import DEFAULT_TOPIC
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID
from utils.ApduDevice import Automation
from utils.CommandBlock import Permissions
from utils.CommandStream import CommandStream
from utils.index import device
from utils.NobleCrypto import Crypto
from utils.streamTree import StreamTree
from utils.test_helpers import create_seed_and_derive_stream, get_ledger_sync_path

valid_member_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK]
valid_member_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]


def _owner_instructions(backend: BackendInterface) -> list:
    return valid_member_instructions_nano if backend.device.is_nano else valid_member_instructions_stax


def test_add_member_on_root_after_derived_stream(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """A policy established on a derived stream must not authorize a member on the root stream.

    The root holds the parent xpriv of every application subtree, and no review screen covers
    it, so the request has to be refused before any UI is shown.
    """
    alice = device.apdu(backend)
    bob = device.software()

    # Establish AppID 16 by completing a normal derived-stream flow
    stream, tree = create_seed_and_derive_stream(alice, 0)
    automation = Automation(navigator, test_name=test_name, instructions=_owner_instructions(backend))
    alice.update_automation(automation)
    stream = stream.edit().add_member("Bob", bob.get_public_key(), Permissions.OWNER, True).issue(alice, tree)
    tree = tree.update(stream)

    # The same session then targets the root Seed stream, which has no application policy
    root = tree.get_root()
    assert root is not None
    with pytest.raises(ExceptionRAPDU):
        root.edit().add_member("Bob", bob.get_public_key(), Permissions.OWNER, False).issue(alice, tree)


def test_add_member_on_root_seed_stream(backend: BackendInterface) -> None:
    """Without any prior derived stream, the root stream refuses ADD_MEMBER as well."""
    alice = device.apdu(backend)
    bob = device.software()
    topic = Crypto.from_hex(DEFAULT_TOPIC)

    root = CommandStream().edit().seed(topic).issue(alice)
    tree = StreamTree.from_streams(root)

    with pytest.raises(ExceptionRAPDU):
        root.edit().add_member("Bob", bob.get_public_key(), Permissions.OWNER, False).issue(alice, tree)


def test_derived_stream_policy_does_not_reach_a_second_derived_stream(
    backend: BackendInterface, navigator: Navigator, test_name: str
) -> None:
    """Each derived stream re-establishes its own policy from its own Derive block.

    Positive control for the reset: AppID 16 still routes correctly on a second subtree
    created in a later signing session.
    """
    alice = device.apdu(backend)
    bob = device.software()

    stream, tree = create_seed_and_derive_stream(alice, 0)
    automation = Automation(navigator, test_name=f"{test_name}/part1", instructions=_owner_instructions(backend))
    alice.update_automation(automation)
    stream = stream.edit().add_member("Bob", bob.get_public_key(), Permissions.OWNER, True).issue(alice, tree)
    tree = tree.update(stream)

    second = CommandStream().edit().derive(get_ledger_sync_path(1)).issue(alice, tree)
    tree = tree.update(second)

    automation = Automation(navigator, test_name=f"{test_name}/part2", instructions=_owner_instructions(backend))
    alice.update_automation(automation)
    second = second.edit().add_member("Bob", bob.get_public_key(), Permissions.OWNER, True).issue(alice, tree)

    assert len(second.get_blocks()[-1].signature) > 0
