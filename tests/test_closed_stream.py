"""Regression tests for the terminal state of a closed stream.

CLOSE_STREAM is the user's removal decision. Once the block carrying it is authenticated, the
stream must not be extended: the device has to refuse to sign, rather than merely answer
SW_STREAM_CLOSED to a host that is free to ignore it.

These tests drive raw APDUs, because the client stops on SW_STREAM_CLOSED and cannot express a
host that carries on regardless.
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
from utils.test_helpers import create_seed_and_derive_stream, get_ledger_sync_path

SW_BAD_STATE = 0xB007
SW_STREAM_CLOSED = 0xB00C
SW_STREAM_PARSER_INVALID_FORMAT = 0xB00A

close_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK]
close_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_REVIEW_TAP]
member_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK]
member_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]


def _close_instructions(backend: BackendInterface) -> list:
    return close_instructions_nano if backend.device.is_nano else close_instructions_stax


def _member_instructions(backend: BackendInterface) -> list:
    return member_instructions_nano if backend.device.is_nano else member_instructions_stax


def _closed_stream(backend: BackendInterface, navigator: Navigator, test_name: str):
    """Build a subtree holding a member, then close it with the user's approval."""
    alice = device.apdu(backend)
    bob = device.software()

    stream, tree = create_seed_and_derive_stream(alice, 0)
    alice.update_automation(Automation(navigator, test_name=f"{test_name}/member", instructions=_member_instructions(backend)))
    stream = stream.edit().add_member("Bob", bob.get_public_key(), Permissions.OWNER, True).issue(alice, tree)
    tree = tree.update(stream)

    alice.update_automation(Automation(navigator, test_name=f"{test_name}/close", instructions=_close_instructions(backend)))
    stream = stream.edit().close().issue(alice, tree)

    root = tree.get_root()
    assert root is not None
    return alice, bob, [root.get_blocks()[0], *stream.get_blocks()]


def _parse_through_close(alice, blocks: list[CommandBlock]):
    """Replay the stream up to and including the authenticated close block.

    The client would stop on SW_STREAM_CLOSED; a hostile host ignores it and sends the close
    block's valid signature anyway, which is what makes the closed block the stream tip.
    """
    Device.initFlow(alice.transport, alice.session_key_pair["publicKey"])
    trusted_params = Device.TrustedParams()
    for block in blocks[:-1]:
        alice.parse_block(block, trusted_params)

    closing = blocks[-1]
    Device.parse_block_header(alice.transport, CommandStreamEncoder.encodeBlockHeader(closing))
    try:
        Device.parseCommand(alice.transport, CommandStreamEncoder.encodeCommand(closing, 0), True)
    except ExceptionRAPDU as error:
        assert error.status == SW_STREAM_CLOSED  # ignored on purpose
    Device.parse_signature(alice.transport, CommandStreamEncoder.encodeSignature(closing))


def test_sign_block_refused_after_close(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """No successor block can be signed once the close block is authenticated."""
    alice, _bob, blocks = _closed_stream(backend, navigator, test_name)
    _parse_through_close(alice, blocks)

    successor = CommandBlock(
        1,
        hash_command_block(blocks[-1]),
        ISSUER_PLACEHOLDER,
        [commands.Derive(get_ledger_sync_path(1), b"", b"", b"", b"")],
        b"",
    )
    with pytest.raises(ExceptionRAPDU) as error:
        Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(successor))
    assert error.value.status == SW_STREAM_CLOSED


def test_publish_key_refused_after_close(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """The retained stream key cannot be published to a member after closure either."""
    alice, bob, blocks = _closed_stream(backend, navigator, test_name)
    _parse_through_close(alice, blocks)

    successor = CommandBlock(
        1,
        hash_command_block(blocks[-1]),
        ISSUER_PLACEHOLDER,
        [commands.PublishKey(b"", b"", bob.get_public_key(), b"")],
        b"",
    )
    with pytest.raises(ExceptionRAPDU) as error:
        Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(successor))
    assert error.value.status == SW_STREAM_CLOSED


def test_finalize_refused_after_close(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """Finalization is gated as well, so no signature can be squeezed out of a closed stream."""
    alice, _bob, blocks = _closed_stream(backend, navigator, test_name)
    _parse_through_close(alice, blocks)

    with pytest.raises(ExceptionRAPDU) as error:
        Device.finalizeSignature(alice.transport)
    assert error.value.status == SW_STREAM_CLOSED


def test_close_stream_still_signs_its_own_block(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """Positive control: the block carrying the approved CLOSE_STREAM is still signed.

    Closure must become terminal only after that block is signed, not while it is being built.
    """
    alice = device.apdu(backend)
    stream, tree = create_seed_and_derive_stream(alice, 0)

    alice.update_automation(Automation(navigator, test_name=test_name, instructions=_close_instructions(backend)))
    stream = stream.edit().close().issue(alice, tree)

    assert len(stream.get_blocks()[-1].signature) > 0


def test_parse_block_header_refused_after_close(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """The parser must not replay a successor to an authenticated close block either.

    Refusing only at SIGN_BLOCK would still let a host rebuild a post-closure trusted member
    and stream key in the parser before switching flows.
    """
    alice, _bob, blocks = _closed_stream(backend, navigator, test_name)
    _parse_through_close(alice, blocks)

    successor = CommandBlock(
        1,
        hash_command_block(blocks[-1]),
        blocks[-1].issuer,
        [commands.Derive(get_ledger_sync_path(1), b"", b"", b"", b"")],
        b"",
    )
    with pytest.raises(ExceptionRAPDU) as error:
        Device.parse_block_header(alice.transport, CommandStreamEncoder.encodeBlockHeader(successor))
    assert error.value.status == SW_STREAM_PARSER_INVALID_FORMAT


def _session_on_open_tip(backend: BackendInterface):
    """Open a session whose stream is parsed up to its verified, still open, tip."""
    alice = device.apdu(backend)
    stream, tree = create_seed_and_derive_stream(alice, 0)
    root = tree.get_root()
    assert root is not None
    blocks = [root.get_blocks()[0], *stream.get_blocks()]

    Device.initFlow(alice.transport, alice.session_key_pair["publicKey"])
    trusted_params = Device.TrustedParams()
    for block in blocks:
        alice.parse_block(block, trusted_params)
    return alice, blocks


def test_sign_block_refuses_a_command_after_close(backend: BackendInterface) -> None:
    """CLOSE_STREAM must be the last command of the block, refused before its approval screen."""
    alice, blocks = _session_on_open_tip(backend)

    block = CommandBlock(
        1,
        hash_command_block(blocks[-1]),
        ISSUER_PLACEHOLDER,
        [commands.CloseStream(), commands.Derive(get_ledger_sync_path(1), b"", b"", b"", b"")],
        b"",
    )
    Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(block))
    with pytest.raises(ExceptionRAPDU) as error:
        Device.signCommand(alice.transport, CommandStreamEncoder.encodeCommand(block, 0))
    assert error.value.status == SW_BAD_STATE


def test_parse_stream_refuses_a_command_after_close(backend: BackendInterface) -> None:
    """A stored block cannot carry commands past its CLOSE_STREAM either."""
    alice, blocks = _session_on_open_tip(backend)

    block = CommandBlock(
        1,
        hash_command_block(blocks[-1]),
        blocks[-1].issuer,
        [commands.CloseStream(), commands.Derive(get_ledger_sync_path(1), b"", b"", b"", b"")],
        b"",
    )
    Device.parse_block_header(alice.transport, CommandStreamEncoder.encodeBlockHeader(block))
    with pytest.raises(ExceptionRAPDU) as error:
        Device.parseCommand(alice.transport, CommandStreamEncoder.encodeCommand(block, 0), True)
    assert error.value.status == SW_STREAM_PARSER_INVALID_FORMAT
