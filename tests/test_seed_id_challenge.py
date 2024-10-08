from pathlib import Path
import hashlib
from typing import Tuple

from ecdsa import VerifyingKey, curves, BadSignatureError  # type: ignore
from ecdsa.util import sigdecode_der  # type: ignore

from ragger.firmware import Firmware
from ragger.navigator import Navigator
from ragger.backend import BackendInterface

from SeedIdClient import SeedIdClient, Errors
from SeedIdChallenge import SeedIdChallenge

from PubKeyCredential import PubKeyCredential

from constants import approve_instructions_nano, approve_instructions_stax

from utils.keychain.keychain import Key, sign_data, get_pub_key


def check_signature(public_key: str,
                    message,
                    signature,
                    curve: curves.Curve = curves.SECP256k1) -> bool:

    vk = VerifyingKey.from_string(public_key, curve=curve, hashfunc=hashlib.sha256)
    try:
        vk.verify(signature, message, hashlib.sha256, sigdecode=sigdecode_der)
    except BadSignatureError:
        return False
    return True


def get_challenge_tlv() -> SeedIdChallenge:
    seed_id_challenge = SeedIdChallenge()

    # Set individual attributes
    seed_id_challenge.payload_type = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.STRUCTURE_TYPE]
    seed_id_challenge.version = 0
    seed_id_challenge.protocol_version = 0x1000000
    seed_id_challenge.challenge_data = bytes.fromhex("53cafde60e5395b164eb867213bc05f6")
    seed_id_challenge.challenge_expiry = 1708678950
    seed_id_challenge.host = b'ATTESTATION_PUBKEY'  # Must be the key trusted name in the Ledger-PKI certificate
    seed_id_challenge.rp_credential_sign_algorithm = SeedIdChallenge.DEFAULT_VALUES[
        SeedIdChallenge.SIGNER_ALGO]
    seed_id_challenge.rp_credential_curve_id = SeedIdChallenge.DEFAULT_VALUES[
        SeedIdChallenge.PUBLIC_KEY_CURVE]

    return seed_id_challenge


def parse_result(result: bytes) -> Tuple[PubKeyCredential, bytes, int, PubKeyCredential, bytes]:
    offset = 0
    pubkey_credential, pubkey_credential_length = PubKeyCredential.from_bytes(result)

    print(pubkey_credential)
    assert pubkey_credential.assert_validity()
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
    assert attestation_pubkey_credential.assert_validity()
    offset += attestation_pubkey_credential_length

    attestation_len = result[offset]
    offset += 1
    attestation = result[offset:offset + attestation_len]
    print("Attestation:", attestation.hex())

    return pubkey_credential, signature, attestation_type, attestation_pubkey_credential, attestation


def test_seed_id_challenge(firmware: Firmware,
                           backend: BackendInterface,
                           navigator: Navigator,
                           default_screenshot_path: Path,
                           test_name: str) -> None:
    if firmware.is_nano:
        approve_seed_id_instructions = approve_instructions_nano
    else:
        approve_seed_id_instructions = approve_instructions_stax

    client = SeedIdClient(backend)

    seed_id_challenge = get_challenge_tlv()
    challenge_hash = seed_id_challenge.get_challenge_hash()
    # Get pub key and sign
    seed_id_challenge.rp_credential_public_key = get_pub_key(Key.CHALLENGE)
    seed_id_challenge.rp_signature = sign_data(Key.CHALLENGE, challenge_hash)

    tlv_data = seed_id_challenge.to_tlv()

    with client.get_seed_id_async(challenge_data=tlv_data):
        navigator.navigate_and_compare(default_screenshot_path,
                                       test_name, approve_seed_id_instructions)

    response = client.seed_id_response()
    assert response and response.status == Errors.SUCCESS

    pubkey, signature, attestation_type, attestation_pubkey, attestation_signature = parse_result(response.data)

    assert attestation_type == 0x00
    assert check_signature(pubkey.public_key, challenge_hash, signature)
    assert check_signature(attestation_pubkey.public_key, hashlib.sha256(
        challenge_hash).digest() + signature, attestation_signature)


# def test_seed_id_invalid_challenge(firmware, backend, navigator, test_name):
    # Should be rejected if challenge is different from what is signed in payload
    # TODO
