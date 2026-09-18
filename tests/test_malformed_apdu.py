"""Malformed APDU regression tests.

Every test here sends a structurally invalid APDU and expects the device to refuse it.
Payloads are built with the TLV helpers so that the malformation stays explicit.
"""

import pytest
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from utils.ApduDevice import Device
from utils.CommandStreamEncoder import TLV
from utils.NobleCrypto import Crypto

BLOCK_VERSION = 0
COMMAND_COUNT = 1
HASH_LEN = 32
MEMBER_KEY_LEN = 33

# Sizes of the header TLVs, in the order the parser expects them.
HEADER_TLV_SIZES = [
    1 + 1 + 1,  # version
    1 + 1 + HASH_LEN,  # parent hash
    1 + 1 + MEMBER_KEY_LEN,  # issuer public key
    1 + 1 + 1,  # command count
]


def _valid_block_header() -> bytearray:
    header = TLV.pushByte(bytearray(), BLOCK_VERSION)
    header = TLV.pushHash(header, Crypto.random_bytes(HASH_LEN))
    header = TLV.pushPublicKey(header, bytes(MEMBER_KEY_LEN))
    return TLV.pushByte(header, COMMAND_COUNT)


def test_sign_block_header_truncated(backend: BackendInterface) -> None:
    """A header truncated at any TLV boundary must be rejected, not parsed from stale state."""
    header = _valid_block_header()

    offset = 0
    for size in HEADER_TLV_SIZES:
        Device.initFlow(backend, Crypto.randomKeyPair()["publicKey"])
        with pytest.raises(ExceptionRAPDU):
            Device.signBlockHeader(backend, header[:offset])
        offset += size

    # The untruncated header is the control case: it must still be accepted.
    Device.initFlow(backend, Crypto.randomKeyPair()["publicKey"])
    Device.signBlockHeader(backend, header)
