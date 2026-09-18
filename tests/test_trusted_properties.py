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
