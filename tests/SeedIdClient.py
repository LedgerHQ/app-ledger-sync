from enum import IntEnum
from typing import Generator, Optional
from contextlib import contextmanager

from ragger.backend import BackendInterface
from ragger.backend.interface import RAPDU
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU


CLA: int = 0xE0


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for maximum APDU number.
    P1_MAX = 0x03
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_CONFIRM = 0x01


class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80


class InsType(IntEnum):
    GET_VERSION = 0x03
    GET_APP_NAME = 0x04
    GET_SEED_ID = 0x05
    SIGN_TX = 0x06


class Errors(IntEnum):
    SUCCESS = 0x9000
    PARSER_INVALID_FORMAT = 0xB00D
    PARSER_INVALID_VALUE = 0xB00E
    CHALLENGE_NOT_VERIFIED = 0xB00F
    NOT_IMPLEMENTED = 0x911c


class PKIPubKeyUsage(IntEnum):
    PUBKEY_USAGE_GENUINE_CHECK = 0x01
    PUBKEY_USAGE_EXCHANGE_PAYLOAD = 0x02
    PUBKEY_USAGE_NFT_METADATA = 0x03
    PUBKEY_USAGE_TRUSTED_NAME = 0x04
    PUBKEY_USAGE_BACKUP_PROVIDER = 0x05
    PUBKEY_USAGE_RECOVER_ORCHESTRATOR = 0x06
    PUBKEY_USAGE_PLUGIN_METADATA = 0x07
    PUBKEY_USAGE_COIN_META = 0x08
    PUBKEY_USAGE_SEED_ID_AUTH = 0x09


class PKIClient:
    _CLA: int = 0xB0
    _INS: int = 0x06

    def __init__(self, client: BackendInterface) -> None:
        self._client = client

    def send_certificate(self, p1: PKIPubKeyUsage, payload: bytes) -> RAPDU:
        try:
            response = self.send_raw(p1, payload)
            assert response.status == Errors.SUCCESS
        except ExceptionRAPDU as err:
            if err.status == Errors.NOT_IMPLEMENTED:
                print("Ledger-PKI APDU not yet implemented. Legacy path will be used")

    def send_raw(self, p1: PKIPubKeyUsage, payload: bytes) -> RAPDU:
        header = bytearray()
        header.append(self._CLA)
        header.append(self._INS)
        header.append(p1)
        header.append(0x00)
        header.append(len(payload))
        return self._client.exchange_raw(header + payload)


class SeedIdClient:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend
        self._firmware = backend.firmware
        self._pki_client: Optional[PKIClient] = None
        if self._firmware != Firmware.NANOS:
            # LedgerPKI not supported on Nanos
            self._pki_client = PKIClient(self.backend)

    def get_seed_id(self, challenge_data: bytes) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_SEED_ID,
                                     p1=P1.P1_START,
                                     p2=P2.P2_LAST,
                                     data=challenge_data)

    @contextmanager
    def get_seed_id_async(self, challenge_data: bytes) -> Generator[None, None, None]:

        if self._pki_client is None:
            print(f"Ledger-PKI Not supported on '{self._firmware.name}'")
        else:
            # pylint: disable=line-too-long
            if self._firmware == Firmware.NANOSP:
                cert_apdu = "0101010201021104000000021201001302000214010116040000000020124154544553544154494F4E5F5055424B4559300200053101093201213321026AC6113CA9EBB823EB7FA40F3E2559A19ACDD7F44B8BF848444ED0CBD60C45A33401013501031546304402200CE5BA4BD3CD260DBE6F21C1EEF7943139ED17BE613BFA75A0661A8CFB98C62702204A6FCBE61EDE30DF97AEFDA364F891EC8BD4AE16DF15BF5BC14CC5399FEE2947"  # noqa: E501
            elif self._firmware == Firmware.NANOX:
                cert_apdu = "0101010201021104000000021201001302000214010116040000000020124154544553544154494F4E5F5055424B4559300200053101093201213321026AC6113CA9EBB823EB7FA40F3E2559A19ACDD7F44B8BF848444ED0CBD60C45A334010135010215473045022100A747641B318C1235F43F483E989AF4CF365BD377E374DF80BBAFEBD84D7E89A302202E4D65141F4A2780AD4F27E419E7F1A21F6D8A71EC2CDF58844F374238BBF399"  # noqa: E501
            elif self._firmware == Firmware.STAX:
                cert_apdu = "0101010201021104000000021201001302000214010116040000000020124154544553544154494F4E5F5055424B4559300200053101093201213321026AC6113CA9EBB823EB7FA40F3E2559A19ACDD7F44B8BF848444ED0CBD60C45A334010135010415463044022005D2B81069EB2D5BD0AE62BB12CBFAB5AA87FFFA739DB6D47FFA659707F0938B022002082016377422A987C80102E4AA7D07CE91A4A3BDB26F67AF397FCCF4661351"  # noqa: E501
            elif self._firmware == Firmware.FLEX:
                cert_apdu = "0101010201021104000000021201001302000214010116040000000020124154544553544154494F4E5F5055424B4559300200053101093201213321026AC6113CA9EBB823EB7FA40F3E2559A19ACDD7F44B8BF848444ED0CBD60C45A334010135010515463044022028A2DA588CAA9040A04E88CC2998268947BE727A6098AA81C283144B88235807022032B875BF38F006A5AB5C436110C3934502E1FFB2A6680546F4A95F0D72693A9B"  # noqa: E501
            # pylint: enable=line-too-long

            self._pki_client.send_certificate(PKIPubKeyUsage.PUBKEY_USAGE_SEED_ID_AUTH, bytes.fromhex(cert_apdu))

        with self.backend.exchange_async(cla=CLA,
                                         ins=InsType.GET_SEED_ID,
                                         p1=P1.P1_START,
                                         p2=P2.P2_LAST,
                                         data=challenge_data) as response:
            yield response

    def seed_id_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response
