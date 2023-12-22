import pytest

from SeedIdClient import SeedIdClient, Errors

from SeedIdChallenge import SeedIdChallenge
from ragger.error import ExceptionRAPDU

from ecdsa import VerifyingKey, curves, BadSignatureError, SigningKey
from ecdsa.util import sigdecode_der, sigencode_der
import hashlib

from PubKeyCredential import PubKeyCredential

PUBLIC_KEY = bytearray.fromhex(
    "041FBEF68DE38F9FACD182C1BC60C3F17290C294CC0D197F57EB645AA43733440A68E8352EC6A76CBF09A93E5B5A6ED2F6676D2A66ED59AFD07AAEB7A19783D8B9")
ATTESTATION_PUBKEY = bytearray.fromhex(
    "04F157320331EA2A70BB3075E8A8E6F9D696816143E9B3D6EB5C1AAB5E6C7D0B693A9DBEF9D5D2C87370999FFD9FD339320ED9012FC6A8BE78F061B857271CDB2B")


def check_signature(public_key, message, signature, curve) -> bool:

    print("------------------------------------")
    print(message)
    print(message.hex())
    vk = VerifyingKey.from_string(public_key, curve=curve, hashfunc=hashlib.sha256)
    try:
        vk.verify(signature, message, hashlib.sha256, sigdecode=sigdecode_der)
    except BadSignatureError:
        return False
    return True


def get_default_challenge_tlv():
    seed_id_challenge = SeedIdChallenge()

    # Set individual attributes
    seed_id_challenge.payload_type = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.STRUCTURE_TYPE]
    seed_id_challenge.version = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.VERSION]
    seed_id_challenge.protocol_version = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.PROTOCOL_VERSION]
    seed_id_challenge.challenge_data = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.CHALLENGE]
    seed_id_challenge.challenge_expiry = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.VALID_UNTIL]
    seed_id_challenge.host = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.TRUSTED_NAME]
    seed_id_challenge.rp_credential_sign_algorithm = SeedIdChallenge.DEFAULT_VALUES[
        SeedIdChallenge.SIGNER_ALGO]
    seed_id_challenge.rp_credential_curve_id = SeedIdChallenge.DEFAULT_VALUES[
        SeedIdChallenge.PUBLIC_KEY_CURVE]
    seed_id_challenge.rp_credential_public_key = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.PUBLIC_KEY]
    seed_id_challenge.rp_signature = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.DER_SIGNATURE]
    tlv_data = seed_id_challenge.to_tlv()

    return tlv_data


def parse_result(result):
    offset = 0
    pubkey_credential, pubkey_credential_length = PubKeyCredential.from_bytes(result)

    print(pubkey_credential)
    assert (pubkey_credential.assert_validity() == True)
    offset += pubkey_credential_length

    signature_len = result[offset]
    offset += 1

    signature = result[offset:offset + signature_len]
    print("Signature:", signature.hex())
    offset += signature_len

    attestation_len = result[offset]
    offset += 1
    attestation = result[offset:offset + attestation_len]
    print("Attestation:", attestation.hex())

    return pubkey_credential, signature, attestation


def test_seed_id(firmware, backend, navigator, test_name):
    client = SeedIdClient(backend)

    tlv_data = get_default_challenge_tlv()

    response = client.get_seed_id(challenge_data=tlv_data)

    assert response.status == 0x9000

    pubkey, signature, challenge = parse_result(response.data)

    assert check_signature(pubkey.public_key, tlv_data, signature, curves.SECP256k1) == True

    assert check_signature(ATTESTATION_PUBKEY, hashlib.sha256(
        tlv_data).digest() + signature, challenge, curves.SECP256k1) == True

    # pubkey, signature, challenge = parse_result(result)
    # assert result is True


# def test_seed_id_invalid_challenge(firmware, backend, navigator, test_name):
    # Should be rejected if challenge is different from what is signed in payload
    # TODO
