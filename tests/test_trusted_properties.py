"""Regression tests on the trusted-property channel itself.

The host holds the session encryption key, so these tests decrypt the properties the
device emitted and assert how they are protected, rather than only that the flow works.
"""

import pytest
from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID
from utils.ApduDevice import Automation, Device
from utils.CommandBlock import Permissions
from utils.index import device
from utils.NobleCrypto import Crypto
from utils.test_helpers import create_seed_and_derive_stream

valid_member_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK]
valid_member_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]


def test_publish_key_properties_use_distinct_ivs(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """A PUBLISH_KEY response carries two encrypted properties, which must not share an IV.

    AES-GCM forbids encrypting twice under the same key and IV, so the trusted member must
    not be readable under the IV that protects the xpriv.
    """
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax

    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()

    stream, tree = create_seed_and_derive_stream(alice, 0)

    # Alice adds Bob, the only step of this flow needing user approval
    member_automation = Automation(navigator, test_name=f"{test_name}_member", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob.get_public_key(), Permissions.OWNER, True).issue(alice, tree)
    tree = tree.update(stream)

    # Bob adds Charlie without publishing the key to him
    stream = stream.edit().add_member("Charlie", charlie.get_public_key(), Permissions.OWNER, False).issue(bob, tree)
    tree = tree.update(stream)

    # Alice publishes the key to Charlie: this response carries both TP_XPRIV and TP_NEW_MEMBER
    stream = stream.edit().publish_key(charlie.get_public_key()).issue(alice, tree)

    properties = alice.last_trusted_properties[-1]
    secret = alice.last_session_secret
    assert isinstance(properties, Device.PublishKeyCommandResponse)

    # The xpriv is protected by the response IV
    Crypto.decrypt(secret, properties.iv, properties.xpriv)

    # The trusted member is not, so the two ciphertexts cannot share a keystream
    with pytest.raises(ValueError):
        Crypto.decrypt(secret, properties.iv, properties.trustedMember)


# Layout of a serialized trusted member: a 4-byte nonce, the stream_trusted_member_t struct
# (33-byte key, 3 bytes of padding, 4-byte permissions, owns_key, 3 bytes of tail padding) and a
# 4-byte checksum over everything before it.
TP_NONCE_LEN = 4
TP_CHECKSUM_LEN = 4
MEMBER_KEY_OFFSET = TP_NONCE_LEN
MEMBER_KEY_LEN = 33
PERMISSIONS_OFFSET = TP_NONCE_LEN + 36
OWNS_KEY_OFFSET = TP_NONCE_LEN + 40
TRUSTED_MEMBER_LEN = TP_NONCE_LEN + 44 + TP_CHECKSUM_LEN

TRUSTED_MEMBER_IV_MASK = 0x5A


def _derive_trusted_member_iv(response_iv: bytes) -> bytes:
    """The device derives the TP_NEW_MEMBER IV from the response IV, see trusted_properties.c."""
    return bytes(b ^ TRUSTED_MEMBER_IV_MASK for b in response_iv)


def test_publish_key_emits_the_serialized_trusted_member(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    """TP_NEW_MEMBER must carry the trusted member, not the command IV it used to alias.

    The property is what a host echoes back through SET_TRUSTED_MEMBER, so it has to
    deserialize: right length, checksum over the nonce and the struct, the recipient's key and
    the owns_key flag the publication just granted.
    """
    if backend.device.is_nano:
        valid_member_instructions = valid_member_instructions_nano
    else:
        valid_member_instructions = valid_member_instructions_stax

    alice = device.apdu(backend)
    bob = device.software()
    charlie = device.software()
    charlie_public_key = bytes(charlie.get_public_key())

    stream, tree = create_seed_and_derive_stream(alice, 0)

    member_automation = Automation(navigator, test_name=f"{test_name}_member", instructions=valid_member_instructions)
    alice.update_automation(member_automation)
    stream = stream.edit().add_member("Bob", bob.get_public_key(), Permissions.OWNER, True).issue(alice, tree)
    tree = tree.update(stream)

    stream = stream.edit().add_member("Charlie", charlie_public_key, Permissions.OWNER, False).issue(bob, tree)
    tree = tree.update(stream)

    stream = stream.edit().publish_key(charlie_public_key).issue(alice, tree)

    properties = alice.last_trusted_properties[-1]
    assert isinstance(properties, Device.PublishKeyCommandResponse)
    member = Crypto.decrypt(alice.last_session_secret, _derive_trusted_member_iv(properties.iv), properties.trustedMember)

    assert len(member) == TRUSTED_MEMBER_LEN
    assert member[-TP_CHECKSUM_LEN:] == Crypto.hash(member[:-TP_CHECKSUM_LEN])[:TP_CHECKSUM_LEN]
    assert member[MEMBER_KEY_OFFSET : MEMBER_KEY_OFFSET + MEMBER_KEY_LEN] == charlie_public_key
    assert member[OWNS_KEY_OFFSET] == 1
    assert int.from_bytes(member[PERMISSIONS_OFFSET : PERMISSIONS_OFFSET + 4], "little") == Permissions.OWNER
