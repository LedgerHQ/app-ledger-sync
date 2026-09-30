"""GET_SEED_ID trusts a relying party key only once a Ledger-PKI certificate pins it.

Kept in its own module so that no certificate loaded by another test is still in place.
"""

import hashlib
from collections.abc import Callable

import pytest
from ecdsa import SECP256k1, SigningKey  # type: ignore
from ecdsa.util import sigencode_der  # type: ignore
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from SeedIdClient import Errors, SeedIdClient
from test_seed_id_challenge import get_challenge_tlv
from utils.keychain.keychain import Key, get_pub_key, sign_data


def _signed_challenge(public_key: bytes, sign: Callable[[bytes], bytes]) -> bytes:
    """Build a well-formed challenge carrying `public_key` and signed with `sign`."""
    challenge = get_challenge_tlv()
    challenge_hash = challenge.get_challenge_hash()
    challenge.rp_credential_public_key = public_key
    challenge.rp_signature = sign(challenge_hash)
    return challenge.to_tlv()


def test_self_signed_challenge_without_certificate_is_refused(backend: BackendInterface) -> None:
    """A challenge signed by the key it carries is refused, before any screen."""
    attacker = SigningKey.generate(curve=SECP256k1, hashfunc=hashlib.sha256)
    challenge = _signed_challenge(
        attacker.get_verifying_key().to_string("compressed"),
        lambda digest: attacker.sign_deterministic(digest, sigencode=sigencode_der),
    )

    with pytest.raises(ExceptionRAPDU) as error:
        SeedIdClient(backend).get_seed_id(challenge_data=challenge)
    assert error.value.status == Errors.CHALLENGE_NOT_VERIFIED


def test_genuine_challenge_without_certificate_is_refused(backend: BackendInterface) -> None:
    """The relying party's own key is not trusted either while no certificate pins it."""
    challenge = _signed_challenge(get_pub_key(Key.CHALLENGE), lambda digest: sign_data(Key.CHALLENGE, digest))

    with pytest.raises(ExceptionRAPDU) as error:
        SeedIdClient(backend).get_seed_id(challenge_data=challenge)
    assert error.value.status == Errors.CHALLENGE_NOT_VERIFIED
