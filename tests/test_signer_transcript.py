"""Regression tests for the signer's per-block transcript.

MODE_BLOCK_START only reinitializes the digest, so the command counters have to belong to the
block currently being signed. Otherwise a host can start a second block, inherit the previous
count, and finalize a header whose commands were never hashed — which also releases the session
public key that unwraps the trusted properties of the abandoned block.

These tests drive raw APDUs, because the client sends exactly one header per session.
"""

import pytest
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from utils.ApduDevice import Device
from utils.CommandBlock import CommandBlock, commands, hash_command_block
from utils.CommandStream import ISSUER_PLACEHOLDER
from utils.CommandStreamEncoder import CommandStreamEncoder
from utils.index import device
from utils.test_helpers import create_seed_and_derive_stream, get_ledger_sync_path

SW_BAD_STATE = 0xB007


def _session_on_stream_tip(backend: BackendInterface):
    """Open a signing session whose stream is parsed up to its verified tip.

    DERIVE is the command used below because it needs no approval screen, so the sequences stay
    pure APDU exchanges.
    """
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


def _block(blocks: list[CommandBlock], command_count: int, index: int = 1) -> CommandBlock:
    """A block to sign, declaring `command_count` commands but holding a single DERIVE."""
    return CommandBlock(
        1,
        hash_command_block(blocks[-1]),
        ISSUER_PLACEHOLDER,
        [commands.Derive(get_ledger_sync_path(index), b"", b"", b"", b"")] * command_count,
        b"",
    )


def test_second_block_start_is_refused(backend: BackendInterface) -> None:
    """Starting a block while one is already in progress must abort the session."""
    alice, blocks = _session_on_stream_tip(backend)

    first = _block(blocks, 1)
    Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(first))

    with pytest.raises(ExceptionRAPDU) as error:
        Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(first))
    assert error.value.status == SW_BAD_STATE


def test_stale_command_count_cannot_finalize_a_header_only_block(backend: BackendInterface) -> None:
    """A restarted block must not inherit the command count of the one it replaced.

    Without the fix the second header reuses parsed_command from the first transcript, so
    finalization matches the counts and signs a block whose command was never hashed into it.
    """
    alice, blocks = _session_on_stream_tip(backend)

    first = _block(blocks, 1)
    Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(first))
    Device.signCommand(alice.transport, CommandStreamEncoder.encodeCommand(first, 0))

    with pytest.raises(ExceptionRAPDU) as error:
        Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(_block(blocks, 1, index=2)))
    assert error.value.status == SW_BAD_STATE

    with pytest.raises(ExceptionRAPDU) as error:
        Device.finalizeSignature(alice.transport)
    assert error.value.status == SW_BAD_STATE


def test_more_commands_than_declared_are_refused(backend: BackendInterface) -> None:
    """A command past the header's declared count belongs to no transcript."""
    alice, blocks = _session_on_stream_tip(backend)

    block = _block(blocks, 1)
    Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(block))
    Device.signCommand(alice.transport, CommandStreamEncoder.encodeCommand(block, 0))

    with pytest.raises(ExceptionRAPDU) as error:
        Device.signCommand(alice.transport, CommandStreamEncoder.encodeCommand(block, 0))
    assert error.value.status == SW_BAD_STATE


def test_declared_commands_still_sign(backend: BackendInterface) -> None:
    """Positive control: a block that parses exactly its declared commands still finalizes."""
    alice, blocks = _session_on_stream_tip(backend)

    block = _block(blocks, 2)
    Device.signBlockHeader(alice.transport, CommandStreamEncoder.encodeBlockHeader(block))
    Device.signCommand(alice.transport, CommandStreamEncoder.encodeCommand(block, 0))
    Device.signCommand(alice.transport, CommandStreamEncoder.encodeCommand(block, 1))

    signature, session_key = Device.finalizeSignature(alice.transport)
    assert len(signature) > 0
    assert len(session_key) > 0
