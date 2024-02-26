import pytest
from pathlib import Path

from SeedIdClient import SeedIdClient, Errors

from SeedIdChallenge import SeedIdChallenge
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID, NavIns, Navigator

from ecdsa import VerifyingKey, curves, BadSignatureError, SigningKey
from ecdsa.util import sigdecode_der, sigencode_der
import hashlib

from PubKeyCredential import PubKeyCredential

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

PUBLIC_KEY = bytearray.fromhex(
    "041FBEF68DE38F9FACD182C1BC60C3F17290C294CC0D197F57EB645AA43733440A68E8352EC6A76CBF09A93E5B5A6ED2F6676D2A66ED59AFD07AAEB7A19783D8B9")

approve_seed_id_instructions_nano = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]

approve_seed_id_instructions_stax = [NavInsID.USE_CASE_CHOICE_CONFIRM]


def check_signature(public_key, message, signature, curve) -> bool:

    vk = VerifyingKey.from_string(public_key, curve=curve, hashfunc=hashlib.sha256)
    try:
        vk.verify(signature, message, hashlib.sha256, sigdecode=sigdecode_der)
    except BadSignatureError:
        return False
    return True


def get_challenge_tlv():
    seed_id_challenge = SeedIdChallenge()

    # Set individual attributes
    seed_id_challenge.payload_type = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.STRUCTURE_TYPE]
    seed_id_challenge.version = 0
    seed_id_challenge.protocol_version = 0x1000000
    seed_id_challenge.challenge_data = bytes.fromhex("53cafde60e5395b164eb867213bc05f6")
    seed_id_challenge.challenge_expiry = 1708678950
    seed_id_challenge.host = b'localhost'
    seed_id_challenge.rp_credential_sign_algorithm = SeedIdChallenge.DEFAULT_VALUES[
        SeedIdChallenge.SIGNER_ALGO]
    seed_id_challenge.rp_credential_curve_id = SeedIdChallenge.DEFAULT_VALUES[
        SeedIdChallenge.PUBLIC_KEY_CURVE]
    seed_id_challenge.rp_credential_public_key = bytes.fromhex(
        "02d89618096b7a88aafca0a2ee483a257cefe4dae1d6d7059e1549b110d3ff575c")
    seed_id_challenge.rp_signature = bytes.fromhex(
        "3045022025d130d7ae5c48a6cf09781d04a08e9a2d07ce1bd17e84637f6ede4a043c5dcc022100a846ececf20eb53ffc2dc502ce8074ba40b241bfd13edaf1e8575559a9b2b4ea")
    return seed_id_challenge


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

    attestation_type = result[offset]
    offset += 1

    attestation_pubkey_credential, attestation_pubkey_credential_length = PubKeyCredential.from_bytes(result,offset=offset)

    print(attestation_pubkey_credential)
    assert (attestation_pubkey_credential.assert_validity() == True)
    offset += attestation_pubkey_credential_length

    attestation_len = result[offset]
    offset += 1
    attestation = result[offset:offset + attestation_len]
    print("Attestation:", attestation.hex())

    return pubkey_credential, signature, attestation_type, attestation_pubkey_credential, attestation


def test_seed_id(firmware, backend, navigator, test_name):
    if firmware.device.startswith("nano"):
        approve_seed_id_instructions = approve_seed_id_instructions_nano
    else:
        approve_seed_id_instructions = approve_seed_id_instructions_stax

    client = SeedIdClient(backend)

    seed_id_challenge = get_challenge_tlv()
    tlv_data = seed_id_challenge.to_tlv()

    challenge_hash = seed_id_challenge.get_challenge_hash()

    with client.get_seed_id_async(challenge_data=tlv_data):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                       test_name, approve_seed_id_instructions)

    response = client.seed_id_response()

    assert response.status == 0x9000

    pubkey, signature, attestation_type, attestation_pubkey, attestation_signature = parse_result(response.data)

    assert attestation_type == 0x00
    assert check_signature(pubkey.public_key, challenge_hash, signature, curves.SECP256k1) == True

    assert check_signature(attestation_pubkey.public_key, hashlib.sha256(
        challenge_hash).digest() + signature, attestation_signature, curves.SECP256k1) == True


# def test_seed_id_invalid_challenge(firmware, backend, navigator, test_name):
    # Should be rejected if challenge is different from what is signed in payload
    # TODO
