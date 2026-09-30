"""Regression tests for the canonical encoding of a command.

The block hasher rebuilds each command from the fields it recognizes, so anything the parser
accepts but does not read is absent from the digest the signature covers. A command therefore
has to have exactly one accepted serialization.

These tests drive raw APDUs, because the client only ever produces canonical commands.
"""

from typing import cast

import pytest
from constants import DEFAULT_TOPIC
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from utils.ApduDevice import Device
from utils.CommandBlock import CommandBlock, Permissions, commands, hash_command_block
from utils.CommandStream import CommandStream
from utils.CommandStreamEncoder import CommandStreamEncoder
from utils.index import device
from utils.NobleCrypto import Crypto
from utils.streamTree import StreamTree
from utils.test_helpers import create_seed_and_derive_stream, get_ledger_sync_path

SW_STREAM_PARSER_INVALID_FORMAT = 0xB00A

COMMAND_CLOSE_STREAM = 0x13


def _append_byte(encoded: bytes) -> bytes:
    """Append one unread byte inside a command's outer TLV value, fixing up its length."""
    command_type, length = encoded[0], encoded[1]
    value = bytes(encoded[2 : 2 + length])
    return bytes([command_type, length + 1]) + value + b"\x00"


def _parsed_root_header(backend: BackendInterface):
    """Open a session and parse the header of a root Seed block, leaving a command expected."""
    alice = device.apdu(backend)
    root_block = create_seed_and_derive_stream(alice, 0)[1].get_root().get_blocks()[0]

    Device.initFlow(alice.transport, alice.session_key_pair["publicKey"])
    Device.parse_block_header(alice.transport, CommandStreamEncoder.encodeBlockHeader(root_block))
    return alice, root_block


def test_trailing_bytes_in_a_parsed_command_are_refused(backend: BackendInterface) -> None:
    """A stored block whose command carries unread trailing bytes must not be accepted."""
    alice, root_block = _parsed_root_header(backend)

    tampered = _append_byte(bytes(CommandStreamEncoder.encodeCommand(root_block, 0)))
    with pytest.raises(ExceptionRAPDU) as error:
        Device.parseCommand(alice.transport, tampered, True)
    assert error.value.status == SW_STREAM_PARSER_INVALID_FORMAT


def test_canonical_command_still_parses(backend: BackendInterface) -> None:
    """Positive control: the same command without the extra byte is accepted."""
    alice, root_block = _parsed_root_header(backend)

    Device.parseCommand(alice.transport, CommandStreamEncoder.encodeCommand(root_block, 0), True)


def _session_on_stream_tip(backend: BackendInterface):
    """Open a session whose stream is parsed to its verified tip, and return its blocks."""
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


def test_close_stream_payload_must_be_empty(backend: BackendInterface) -> None:
    """CLOSE_STREAM is hashed with an empty value, so only an empty value can be accepted.

    A non-empty payload would be a carrier for bytes the signature never covers. Driven through
    PARSE_STREAM, where the command needs no approval screen: the pre-fix device accepts the
    payload and answers SW_STREAM_CLOSED, the fixed one rejects the encoding.
    """
    alice, blocks = _session_on_stream_tip(backend)

    header = CommandBlock(1, hash_command_block(blocks[-1]), blocks[-1].issuer, [commands.CloseStream()], b"")
    Device.parse_block_header(alice.transport, CommandStreamEncoder.encodeBlockHeader(header))

    with pytest.raises(ExceptionRAPDU) as error:
        Device.parseCommand(alice.transport, bytes([COMMAND_CLOSE_STREAM, 1, 0x00]), True)
    assert error.value.status == SW_STREAM_PARSER_INVALID_FORMAT


def test_add_member_name_with_embedded_nul_is_refused(backend: BackendInterface) -> None:
    """An embedded NUL makes the hashed name shorter than the name that was accepted.

    Driven through PARSE_STREAM, where ADD_MEMBER needs no approval screen: the pre-fix device
    records the truncated member and answers success, the fixed one rejects the encoding.
    """
    alice, blocks = _session_on_stream_tip(backend)
    bob = device.software()

    member = commands.AddMember("Bob", bob.get_public_key(), Permissions.OWNER)
    header = CommandBlock(1, hash_command_block(blocks[-1]), blocks[-1].issuer, [member], b"")
    Device.parse_block_header(alice.transport, CommandStreamEncoder.encodeBlockHeader(header))

    encoded = bytes(CommandStreamEncoder.encodeCommand(header, 0))
    assert b"Bob" in encoded
    tampered = encoded.replace(b"Bob", b"B\x00b", 1)

    with pytest.raises(ExceptionRAPDU) as error:
        Device.parseCommand(alice.transport, tampered, True)
    assert error.value.status == SW_STREAM_PARSER_INVALID_FORMAT


def test_seed_topic_is_unaffected(backend: BackendInterface) -> None:
    """Positive control: a normal seed flow, whose topic is a full-length field, still signs."""
    alice = device.apdu(backend)
    stream, _tree = create_seed_and_derive_stream(alice, 0, topic=Crypto.from_hex(DEFAULT_TOPIC))
    assert len(stream.get_blocks()[-1].signature) > 0


def _parsed_foreign_seed_header(backend: BackendInterface):
    """Open a session and parse the header of a root Seed block issued by another member."""
    alice = device.apdu(backend)
    root = CommandStream().edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(device.software())
    seed_block = root.get_blocks()[0]

    Device.initFlow(alice.transport, alice.session_key_pair["publicKey"])
    Device.parse_block_header(alice.transport, CommandStreamEncoder.encodeBlockHeader(seed_block))
    return alice, seed_block


@pytest.mark.parametrize("field", ["initialization_vector", "encrypted_xpriv"])
def test_short_seed_key_field_is_refused(backend: BackendInterface, field: str) -> None:
    """A stored Seed carries a full IV and encrypted xpriv, the sizes its digest covers."""
    alice, seed_block = _parsed_foreign_seed_header(backend)
    seed = seed_block.commands[0]
    setattr(seed, field, getattr(seed, field)[:-1])

    with pytest.raises(ExceptionRAPDU) as error:
        Device.parseCommand(alice.transport, CommandStreamEncoder.encodeCommand(seed_block, 0), True)
    assert error.value.status == SW_STREAM_PARSER_INVALID_FORMAT


def test_short_derive_key_field_is_refused(backend: BackendInterface) -> None:
    """A stored Derive carries a full IV too."""
    alice = device.apdu(backend)
    bob = device.software()
    root = CommandStream().edit().seed(Crypto.from_hex(DEFAULT_TOPIC)).issue(bob)
    tree = StreamTree.from_streams(root)
    derived = CommandStream().edit().derive(get_ledger_sync_path(0)).issue(bob, tree)
    seed_block, derive_block = root.get_blocks()[0], derived.get_blocks()[0]

    Device.initFlow(alice.transport, alice.session_key_pair["publicKey"])
    alice.parse_block(seed_block, Device.TrustedParams())
    Device.parse_block_header(alice.transport, CommandStreamEncoder.encodeBlockHeader(derive_block))

    derive = cast(commands.Derive, derive_block.commands[0])
    derive.initialization_vector = derive.initialization_vector[:-1]
    with pytest.raises(ExceptionRAPDU) as error:
        Device.parseCommand(alice.transport, CommandStreamEncoder.encodeCommand(derive_block, 0), True)
    assert error.value.status == SW_STREAM_PARSER_INVALID_FORMAT


def test_complete_foreign_seed_still_parses(backend: BackendInterface) -> None:
    """Positive control: the same Seed with its fields intact is accepted."""
    alice, seed_block = _parsed_foreign_seed_header(backend)

    Device.parseCommand(alice.transport, CommandStreamEncoder.encodeCommand(seed_block, 0), True)
