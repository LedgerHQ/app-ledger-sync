"""User approval enforcement regression tests.

Refusing a command on screen must abort the whole signing session. The SDK rejects APDUs
while a reply is pending, so these tests cover what happens once the refusal has been
answered: the host must not be able to carry on with the block the user just refused.
"""

import pytest
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID
from utils.ApduDevice import Automation, Device
from utils.CommandBlock import Permissions
from utils.index import device
from utils.test_helpers import create_seed_and_derive_stream

decline_member_instructions_nano = [
    NavInsID.RIGHT_CLICK,
    NavInsID.RIGHT_CLICK,
    NavInsID.RIGHT_CLICK,
    NavInsID.BOTH_CLICK,
]
decline_member_instructions_stax = [NavInsID.USE_CASE_CHOICE_REJECT, NavInsID.USE_CASE_STATUS_DISMISS]

SW_BAD_STATE = 0xB007
SW_DENY = 0x6985

# The CLOSE_STREAM choice has no description page, so it needs one step less than ADD_MEMBER
decline_close_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
decline_close_instructions_stax = [NavInsID.USE_CASE_CHOICE_REJECT, NavInsID.USE_CASE_STATUS_DISMISS]


# TLV types of a PublishKey command payload, built by hand because the client aborts the
# signing flow as soon as the device refuses a command.
TLV_BYTES = 0x05
TLV_PUBKEY = 0x06
COMMAND_PUBLISH_KEY = 0x12


def _decline_instructions(backend: BackendInterface) -> list:
    if backend.device.is_nano:
        return decline_member_instructions_nano
    return decline_member_instructions_stax


def _refuse_add_member(backend: BackendInterface, navigator: Navigator, test_name: str, publish_key: bool):
    """Drive a block holding an ADD_MEMBER up to its approval screen, and refuse it."""
    alice = device.apdu(backend)
    bob = device.software()
    bob_public_key = bob.get_public_key()
    stream, tree = create_seed_and_derive_stream(alice, 0)

    automation = Automation(navigator, test_name=test_name, instructions=_decline_instructions(backend))
    alice.update_automation(automation)
    with pytest.raises(ExceptionRAPDU) as error:
        stream.edit().add_member("Bob", bob_public_key, Permissions.OWNER, publish_key).issue(alice, tree)
    assert error.value.status == 0x6985

    return bob_public_key


def test_refused_add_member_cannot_be_finalized(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """A block whose only command was refused must not yield a signature."""
    _refuse_add_member(backend, navigator, test_name, publish_key=False)

    with pytest.raises(ExceptionRAPDU) as error:
        Device.finalizeSignature(backend)
    assert error.value.status == SW_BAD_STATE


def test_refused_add_member_stops_the_rest_of_the_block(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """Refusing ADD_MEMBER must also stop the PUBLISH_KEY that follows it in the same block.

    That command would otherwise hand the stream key to the member the user just refused.
    """
    bob_public_key = _refuse_add_member(backend, navigator, test_name, publish_key=True)

    # PublishKey with empty placeholders for the fields the device generates itself
    payload = bytes([TLV_BYTES, 0, TLV_BYTES, 0, TLV_PUBKEY, len(bob_public_key)])
    payload += bytes(bob_public_key) + bytes([TLV_PUBKEY, 0])
    command = bytes([COMMAND_PUBLISH_KEY, len(payload)]) + payload

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(Device.CLA, Device.INS_SIGN_BLOCK, 0x01, 0x00, command)
    assert error.value.status == SW_BAD_STATE


def test_refused_close_stream_cannot_be_finalized(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """Refusing CLOSE_STREAM must abort the session too.

    That refusal goes through update_confirm() rather than the shared UI deny callback, so it
    needs its own coverage. The block holds a single command, so finalization is the assertion
    that discriminates: without the reset the signer still counts the refused command and signs.
    """
    decline = decline_close_instructions_nano if backend.device.is_nano else decline_close_instructions_stax

    alice = device.apdu(backend)
    stream, tree = create_seed_and_derive_stream(alice, 0)

    automation = Automation(navigator, test_name=test_name, instructions=decline)
    alice.update_automation(automation)
    with pytest.raises(ExceptionRAPDU) as error:
        stream.edit().close().issue(alice, tree)
    assert error.value.status == SW_DENY

    with pytest.raises(ExceptionRAPDU) as error:
        Device.finalizeSignature(backend)
    assert error.value.status == SW_BAD_STATE
