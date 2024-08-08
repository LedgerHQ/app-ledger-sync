from pathlib import Path
import pytest

from ragger.error import ExceptionRAPDU
from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from SeedIdClient import SeedIdClient, Errors
from SeedIdChallenge import SeedIdChallenge

from constants import approve_instructions_nano, approve_instructions_stax


def get_default_challenge_tlv() -> bytes:
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


def test_seed_id_parser(firmware: Firmware,
                        backend: BackendInterface,
                        navigator: Navigator,
                        default_screenshot_path: Path,
                        test_name: str) -> None:
    if firmware.is_nano:
        approve_seed_id_instructions = approve_instructions_nano
    else:
        approve_seed_id_instructions = approve_instructions_stax

    client = SeedIdClient(backend)

    tlv_data = get_default_challenge_tlv()

    with client.get_seed_id_async(challenge_data=tlv_data):
        navigator.navigate_and_compare(default_screenshot_path, test_name, approve_seed_id_instructions)

    response = client.seed_id_response()
    assert response and response.status == Errors.SUCCESS


def test_seed_id_wrong_structure_type(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    # Override STRUCTURE_TYPE with unsupported data
    tlv_data = get_default_challenge_tlv()
    data1 = 0x66
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.STRUCTURE_TYPE, data1)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE

    # Override STRUCTURE_TYPE with unsupported length
    tlv_data = get_default_challenge_tlv()
    data2 = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.STRUCTURE_TYPE]
    length = 0x10
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.STRUCTURE_TYPE, data2, length)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE


def test_seed_id_wrong_version(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    # Override VERSION with unsupported data
    tlv_data = get_default_challenge_tlv()
    data1 = 0x66
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.VERSION, data1)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE

    # Override VERSION with unsupported length
    tlv_data = get_default_challenge_tlv()
    data2 = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.VERSION]
    length = 0x10
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.VERSION, data2, length)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE


def test_seed_id_wrong_challenge(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    # Override CHALLENGE with unsupported length
    tlv_data = get_default_challenge_tlv()
    data = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.CHALLENGE]
    length = 0x11
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.CHALLENGE, data, length)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE


def test_seed_id_wrong_signer_algo(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    # Override SIGNER_ALGO with unsupported data
    tlv_data = get_default_challenge_tlv()
    data1 = 0x66
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.SIGNER_ALGO, data1)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE

    # Override SIGNER_ALGO with unsupported length
    tlv_data = get_default_challenge_tlv()
    data2 = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.SIGNER_ALGO]
    length = 0x10
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.SIGNER_ALGO, data2, length)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE


def test_seed_id_wrong_signature(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    # Override DER_SIGNATURE with unsupported length
    tlv_data = get_default_challenge_tlv()
    data = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.DER_SIGNATURE]
    length = 0x10
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.DER_SIGNATURE, data, length)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_FORMAT


def test_seed_id_wrong_valid_until(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    # Override VALID_UNTIL with unsupported length
    tlv_data = get_default_challenge_tlv()
    data = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.VALID_UNTIL]
    length = 0x10
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.VALID_UNTIL, data, length)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE


def test_seed_id_wrong_trusted_name(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    # Override TRUSTED_NAME with unsupported length
    tlv_data = get_default_challenge_tlv()
    data = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.TRUSTED_NAME]
    length = 0x10
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.TRUSTED_NAME, data, length)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE


def test_seed_id_wrong_public_key_curve(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    # Override PUBLIC_KEY_CURVE with unsupported data
    tlv_data = get_default_challenge_tlv()
    data1 = 0x66
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.PUBLIC_KEY_CURVE, data1)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE

    # Override PUBLIC_KEY_CURVE with unsupported length
    tlv_data = get_default_challenge_tlv()
    data2 = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.PUBLIC_KEY_CURVE]
    length = 0x10
    tlv_data = SeedIdChallenge.update_field(
        tlv_data, SeedIdChallenge.PUBLIC_KEY_CURVE, data2, length)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE


def test_seed_id_wrong_public_key(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    # Override PUBLIC_KEY with unsupported length
    tlv_data = get_default_challenge_tlv()
    data = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.PUBLIC_KEY]
    length = 0x10
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.PUBLIC_KEY, data, length)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_FORMAT


def test_seed_id_wrong_protocol_version(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    # Override PROTOCOL_VERSION with unsupported data
    tlv_data = get_default_challenge_tlv()
    data1= 0x66
    tlv_data = SeedIdChallenge.update_field(tlv_data, SeedIdChallenge.PROTOCOL_VERSION, data1)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE

    # Override PROTOCOL_VERSION with unsupported length
    tlv_data = get_default_challenge_tlv()
    data2 = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.PROTOCOL_VERSION]
    length = 0x10
    tlv_data = SeedIdChallenge.update_field(
        tlv_data, SeedIdChallenge.PROTOCOL_VERSION, data2, length)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_FORMAT


def test_seed_id_extra_data(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    tlv_data = get_default_challenge_tlv()
    tlv_data += b'00000'

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_FORMAT


def test_seed_id_missing_field(backend: BackendInterface) -> None:
    client = SeedIdClient(backend)

    seed_id_challenge = SeedIdChallenge()

    seed_id_challenge.payload_type = None
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

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE
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
    seed_id_challenge.rp_signature = None
    tlv_data = seed_id_challenge.to_tlv()

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE

    seed_id_challenge.payload_type = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.STRUCTURE_TYPE]
    seed_id_challenge.version = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.VERSION]
    seed_id_challenge.protocol_version = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.PROTOCOL_VERSION]
    seed_id_challenge.challenge_data = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.CHALLENGE]
    seed_id_challenge.challenge_expiry = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.VALID_UNTIL]
    seed_id_challenge.host = None
    seed_id_challenge.rp_credential_sign_algorithm = SeedIdChallenge.DEFAULT_VALUES[
        SeedIdChallenge.SIGNER_ALGO]
    seed_id_challenge.rp_credential_curve_id = SeedIdChallenge.DEFAULT_VALUES[
        SeedIdChallenge.PUBLIC_KEY_CURVE]
    seed_id_challenge.rp_credential_public_key = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.PUBLIC_KEY]
    seed_id_challenge.rp_signature = SeedIdChallenge.DEFAULT_VALUES[SeedIdChallenge.DER_SIGNATURE]
    tlv_data = seed_id_challenge.to_tlv()

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_seed_id(challenge_data=tlv_data)
    assert e.value.status == Errors.PARSER_INVALID_VALUE
