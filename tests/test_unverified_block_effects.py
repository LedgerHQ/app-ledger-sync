"""Regression tests for the effects of a block that is never proven to be signed.

PARSE_STREAM applies a command as soon as it is read, but the issuer signature only arrives in a
later APDU that the host is free to skip or get wrong. A block must therefore change nothing the
signer can build on until its signature verifies, and SIGN_BLOCK must refuse to start while a
block is still pending.

These tests drive raw APDUs, because the client always submits whole signed blocks and cannot
express the sequences below.
"""

import pytest
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID
from utils.ApduDevice import Automation, Device
from utils.CommandBlock import CommandBlock, Permissions, commands, hash_command_block
from utils.CommandStream import ISSUER_PLACEHOLDER
from utils.CommandStreamEncoder import CommandStreamEncoder
from utils.index import device
from utils.NobleCrypto import Crypto
from utils.test_helpers import create_seed_and_derive_stream

SW_BAD_STATE = 0xB007
SW_STREAM_PARSER_INVALID_FORMAT = 0xB00A
SW_WRONG_DATA = 0x6A80

valid_member_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK]
valid_member_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]


def _owner_instructions(backend: BackendInterface) -> list:
    return valid_member_instructions_nano if backend.device.is_nano else valid_member_instructions_stax


def _legitimate_stream(backend: BackendInterface, navigator: Navigator, test_name: str):
    """Build a Ledger Sync subtree holding a member, and return its blocks oldest first."""
    alice = device.apdu(backend)
    bob = device.software()

    stream, tree = create_seed_and_derive_stream(alice, 0)
    automation = Automation(navigator, test_name=test_name, instructions=_owner_instructions(backend))
    alice.update_automation(automation)
    stream = stream.edit().add_member("Bob", bob.get_public_key(), Permissions.OWNER, True).issue(alice, tree)

    root = tree.get_root()
    assert root is not None
    return alice, [root.get_blocks()[0], *stream.get_blocks()]


def _parse_through_tip(alice, blocks: list[CommandBlock]):
    """Replay the whole stream, signatures included, leaving the parser on the verified tip."""
    Device.initFlow(alice.transport, alice.session_key_pair["publicKey"])
    trusted_params = Device.TrustedParams()
    for block in blocks:
        alice.parse_block(block, trusted_params)


def _inject_unsigned_add_member(alice, blocks: list[CommandBlock], attacker_public_key: bytes) -> CommandBlock:
    """Parse a self-issued child block holding ADD_MEMBER, and never send its signature."""
    return _capture_unsigned_member(alice, blocks, attacker_public_key)[0]


def _capture_unsigned_member(alice, blocks: list[CommandBlock], attacker_public_key: bytes):
    """Same as above, also keeping the TP_NEW_MEMBER the device issued for the unsigned member."""
    forged = CommandBlock(
        1,
        hash_command_block(blocks[-1]),
        blocks[-1].issuer,  # the device is the issuer the header claims
        [commands.AddMember("Attacker", attacker_public_key, Permissions.OWNER)],
        b"",
    )
    Device.parse_block_header(alice.transport, CommandStreamEncoder.encodeBlockHeader(forged))
    result = Device.parseCommand(alice.transport, CommandStreamEncoder.encodeCommand(forged, 0), True)

    captured = Device.TrustedParams()
    alice.record_trusted_member(captured, attacker_public_key, result)
    return forged, alice.get_trusted_member(captured, attacker_public_key)


def _publish_key_block(blocks: list[CommandBlock], recipient: bytes) -> CommandBlock:
    return CommandBlock(
        1,
        hash_command_block(blocks[-1]),
        ISSUER_PLACEHOLDER,
        [commands.PublishKey(b"", b"", recipient, b"")],
        b"",
    )


def test_sign_block_refuses_to_start_on_a_pending_block(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """With an unsigned ADD_MEMBER pending, SIGN_BLOCK must not start at all."""
    attacker = device.software()
    alice, blocks = _legitimate_stream(backend, navigator, test_name)

    _parse_through_tip(alice, blocks)
    _inject_unsigned_add_member(alice, blocks, attacker.get_public_key())

    to_sign = _publish_key_block(blocks, attacker.get_public_key())
    with pytest.raises(ExceptionRAPDU) as error:
        Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(to_sign))
    assert error.value.status == SW_BAD_STATE


def test_omitted_signature_rolls_back_the_injected_member(
    backend: BackendInterface, navigator: Navigator, test_name: str
) -> None:
    """Re-syncing the parser must leave the trusted member as the verified tip left it.

    The host walks away from the block it never signed, so the injected member is gone and the
    key it was meant to receive cannot be published to it.
    """
    attacker = device.software()
    alice, blocks = _legitimate_stream(backend, navigator, test_name)

    _parse_through_tip(alice, blocks)
    _inject_unsigned_add_member(alice, blocks, attacker.get_public_key())

    # Abandon the pending block and return the parser to the verified tip
    Device.parseEmptyStream(alice.transport)

    to_sign = _publish_key_block(blocks, attacker.get_public_key())
    Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(to_sign))
    with pytest.raises(ExceptionRAPDU) as error:
        Device.signCommand(alice.transport, CommandStreamEncoder.encodeCommand(to_sign, 0))
    assert error.value.status == SW_BAD_STATE


def test_invalid_signature_rolls_back_the_injected_member(
    backend: BackendInterface, navigator: Navigator, test_name: str
) -> None:
    """An unverifiable signature must discard the block's effects rather than keep them."""
    attacker = device.software()
    alice, blocks = _legitimate_stream(backend, navigator, test_name)

    _parse_through_tip(alice, blocks)
    forged = _inject_unsigned_add_member(alice, blocks, attacker.get_public_key())

    forged.signature = Crypto.random_bytes(70)
    with pytest.raises(ExceptionRAPDU) as error:
        Device.parse_signature(alice.transport, CommandStreamEncoder.encodeSignature(forged))
    assert error.value.status == SW_STREAM_PARSER_INVALID_FORMAT

    to_sign = _publish_key_block(blocks, attacker.get_public_key())
    Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(to_sign))
    with pytest.raises(ExceptionRAPDU) as error:
        Device.signCommand(alice.transport, CommandStreamEncoder.encodeCommand(to_sign, 0))
    assert error.value.status == SW_BAD_STATE


@pytest.mark.parametrize("drop", ["omitted_signature", "invalid_signature"])
def test_member_from_a_dropped_block_cannot_be_replayed(
    backend: BackendInterface, navigator: Navigator, test_name: str, drop: str
) -> None:
    """The TP_NEW_MEMBER issued for an unsigned block must not be accepted back once it is dropped.

    Rolling the block back is not enough on its own: SET_TRUSTED_MEMBER would reinstall the
    member the host captured while the block was pending.
    """
    attacker = device.software()
    alice, blocks = _legitimate_stream(backend, navigator, test_name)

    _parse_through_tip(alice, blocks)
    forged, captured = _capture_unsigned_member(alice, blocks, attacker.get_public_key())

    if drop == "omitted_signature":
        Device.parseEmptyStream(alice.transport)
    else:
        forged.signature = Crypto.random_bytes(70)
        with pytest.raises(ExceptionRAPDU):
            Device.parse_signature(alice.transport, CommandStreamEncoder.encodeSignature(forged))

    with pytest.raises(ExceptionRAPDU) as error:
        Device.set_trusted_member(alice.transport, captured)
    assert error.value.status == SW_WRONG_DATA

    to_sign = _publish_key_block(blocks, attacker.get_public_key())
    Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(to_sign))
    with pytest.raises(ExceptionRAPDU) as error:
        Device.signCommand(alice.transport, CommandStreamEncoder.encodeCommand(to_sign, 0))
    assert error.value.status == SW_BAD_STATE


def test_parse_stream_refused_while_a_block_is_being_signed(backend: BackendInterface) -> None:
    """The parser must not move under a block being signed, or the signer would use its effects.

    The host starts signing a PUBLISH_KEY to its own key, slips an unsigned ADD_MEMBER for that
    key through PARSE_STREAM, then resumes signing.
    """
    alice = device.apdu(backend)
    attacker = device.software()
    stream, tree = create_seed_and_derive_stream(alice, 0)
    root = tree.get_root()
    assert root is not None
    blocks = [root.get_blocks()[0], *stream.get_blocks()]
    _parse_through_tip(alice, blocks)

    to_sign = _publish_key_block(blocks, attacker.get_public_key())
    Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(to_sign))

    forged = CommandBlock(
        1,
        hash_command_block(blocks[-1]),
        blocks[-1].issuer,
        [commands.AddMember("Attacker", attacker.get_public_key(), Permissions.OWNER)],
        b"",
    )
    with pytest.raises(ExceptionRAPDU) as error:
        Device.parse_block_header(alice.transport, CommandStreamEncoder.encodeBlockHeader(forged))
    assert error.value.status == SW_BAD_STATE

    with pytest.raises(ExceptionRAPDU) as error:
        Device.signCommand(alice.transport, CommandStreamEncoder.encodeCommand(to_sign, 0))
    assert error.value.status == SW_BAD_STATE
