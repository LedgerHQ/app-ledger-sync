"""PUBLISH_KEY recipient authorization regression tests.

Matching the recipient key against the recorded trusted member is not authorization: the
recipient must also hold a permission set the user approved for key access. These tests drive
the recipients that pass the key check but must be refused at the encryption sink.
"""

import pytest
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID
from test_agent_intent import (
    AGENT_FIXED_PRIVATE_KEY,
    create_agent_intent_stream,
    enable_agent_access_happy_nano,
    enable_agent_access_happy_stax,
    register_agent_happy_nano,
    register_agent_happy_stax,
)
from utils.ApduDevice import Automation
from utils.CommandBlock import Permissions
from utils.index import device
from utils.test_helpers import create_seed_and_derive_stream

SW_BAD_STATE = 0xB007

valid_member_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK]
valid_member_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]


def _register_instructions(backend: BackendInterface) -> list:
    return register_agent_happy_nano if backend.device.is_nano else register_agent_happy_stax


def _enable_access_instructions(backend: BackendInterface) -> list:
    return enable_agent_access_happy_nano if backend.device.is_nano else enable_agent_access_happy_stax


def _owner_instructions(backend: BackendInterface) -> list:
    return valid_member_instructions_nano if backend.device.is_nano else valid_member_instructions_stax


def test_publish_key_to_registered_agent_in_same_block(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """An identify-only agent must not receive the key through the block that registers it."""
    alice = device.apdu(backend)
    agent = device.software_from_key(AGENT_FIXED_PRIVATE_KEY)
    stream, tree = create_agent_intent_stream(alice)

    automation = Automation(navigator, test_name=test_name, instructions=_register_instructions(backend))
    alice.update_automation(automation)
    with pytest.raises(ExceptionRAPDU) as error:
        stream.edit().add_member("Bob's agent", agent.get_public_key(), Permissions.AGENT_REGISTER, publish_key=True).issue(
            alice, tree
        )
    assert error.value.status == SW_BAD_STATE


def test_publish_key_to_registered_agent_in_later_block(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """Nor through a later session, after the registration block has been parsed back."""
    alice = device.apdu(backend)
    agent = device.software_from_key(AGENT_FIXED_PRIVATE_KEY)
    agent_pubkey = agent.get_public_key()
    stream, tree = create_agent_intent_stream(alice)

    automation = Automation(navigator, test_name=test_name, instructions=_register_instructions(backend))
    alice.update_automation(automation)
    stream = (
        stream.edit().add_member("Bob's agent", agent_pubkey, Permissions.AGENT_REGISTER, publish_key=False).issue(alice, tree)
    )
    tree = tree.update(stream)

    with pytest.raises(ExceptionRAPDU) as error:
        stream.edit().publish_key(agent_pubkey).issue(alice, tree)
    assert error.value.status == SW_BAD_STATE


def test_publish_key_to_full_access_agent(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """Positive control: the separately approved full-access role does receive the key."""
    alice = device.apdu(backend)
    agent = device.software_from_key(AGENT_FIXED_PRIVATE_KEY)
    stream, tree = create_agent_intent_stream(alice)

    automation = Automation(navigator, test_name=test_name, instructions=_enable_access_instructions(backend))
    alice.update_automation(automation)
    stream = (
        stream.edit()
        .add_member("Bob's agent", agent.get_public_key(), Permissions.AGENT_FULL, publish_key=True)
        .issue(alice, tree)
    )

    assert len(stream.get_blocks()[-1].signature) > 0


def test_publish_key_to_member_without_can_encrypt(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """On a Ledger Sync stream, a member registered without CAN_ENCRYPT cannot receive the key.

    Such a permission set never comes from the device's own review screens, only from a member
    added by another device, so it has to be refused at the PUBLISH_KEY sink.
    """
    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()
    charlie_public_key = charlie.get_public_key()

    stream, tree = create_seed_and_derive_stream(alice, 0)

    automation = Automation(navigator, test_name=test_name, instructions=_owner_instructions(backend))
    alice.update_automation(automation)
    stream = stream.edit().add_member("Bob", bob.get_public_key(), Permissions.OWNER, True).issue(alice, tree)
    tree = tree.update(stream)

    # Bob grants Charlie derivation only, without the encryption capability
    stream = stream.edit().add_member("Charlie", charlie_public_key, Permissions.CAN_DERIVE, False).issue(bob, tree)
    tree = tree.update(stream)

    with pytest.raises(ExceptionRAPDU) as error:
        stream.edit().publish_key(charlie_public_key).issue(alice, tree)
    assert error.value.status == SW_BAD_STATE
