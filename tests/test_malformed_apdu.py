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
IV_LEN = 16
GCM_TAG_LEN = 16
SW_WRONG_DATA = 0x6A80

# Encrypted trusted member, as the device emits it in a TP_NEW_MEMBER trusted property:
# TP_NONCE_SIZE, stream_trusted_member_t (33-byte key + 4-byte permissions + 1 flag,
# padded to 44), TP_CHECKSUM_LEN, then the GCM tag appended by the encryption.
TRUSTED_MEMBER_PLAIN_LEN = 4 + 44 + 4
TRUSTED_MEMBER_ENCRYPTED_LEN = TRUSTED_MEMBER_PLAIN_LEN + GCM_TAG_LEN

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


def _trusted_property(property_type: int, value: bytes) -> bytes:
    return bytes([property_type, len(value)]) + value


def _set_trusted_member(backend: BackendInterface, payload: bytes) -> None:
    backend.exchange(Device.CLA, Device.INS_SET_TRUSTED_MEMBER, 0, 0, payload)


def test_set_trusted_member_short_iv(backend: BackendInterface) -> None:
    """An IV shorter than the AES-GCM block must be refused before it reaches the crypto layer."""
    Device.initFlow(backend, Crypto.randomKeyPair()["publicKey"])
    member = _trusted_property(Device.TrustedPropertiesTLV.TrustedMember, bytes(TRUSTED_MEMBER_ENCRYPTED_LEN))

    for iv_len in range(IV_LEN):
        iv = _trusted_property(Device.TrustedPropertiesTLV.IV, bytes(iv_len))
        # Both orders matter: a trailing short IV is the case that reads past the APDU.
        for payload in (iv + member, member + iv):
            with pytest.raises(ExceptionRAPDU) as error:
                _set_trusted_member(backend, payload)
            assert error.value.status == SW_WRONG_DATA


def test_set_trusted_member_invalid_ciphertext_length(backend: BackendInterface) -> None:
    """Only the exact encrypted trusted member length may reach the AES-GCM decryption."""
    Device.initFlow(backend, Crypto.randomKeyPair()["publicKey"])
    iv = _trusted_property(Device.TrustedPropertiesTLV.IV, bytes(IV_LEN))

    shorter_than_tag = list(range(GCM_TAG_LEN))
    other_lengths = [GCM_TAG_LEN, TRUSTED_MEMBER_ENCRYPTED_LEN - 1, TRUSTED_MEMBER_ENCRYPTED_LEN + 1, 200]

    for member_len in shorter_than_tag + other_lengths:
        member = _trusted_property(Device.TrustedPropertiesTLV.TrustedMember, bytes(member_len))
        with pytest.raises(ExceptionRAPDU) as error:
            _set_trusted_member(backend, iv + member)
        assert error.value.status == SW_WRONG_DATA
