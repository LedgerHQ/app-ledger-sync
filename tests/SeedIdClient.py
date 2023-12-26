from ragger.backend.interface import BackendInterface, RAPDU
from enum import IntEnum
from typing import Generator, List, Optional
from contextlib import contextmanager

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
    PARSER_INVALID_FORMAT = 0xB00D
    PARSER_INVALID_VALUE = 0xB00E
    CHALLENGE_NOT_VERIFIED = 0xB00F


class SeedIdClient:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def get_seed_id(self, challenge_data: bytes) -> Generator[None, None, None]:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_SEED_ID,
                                     p1=P1.P1_START,
                                     p2=P2.P2_LAST,
                                     data=challenge_data)

    @contextmanager
    def get_seed_id_async(self, challenge_data: bytes) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA,
                                         ins=InsType.GET_SEED_ID,
                                         p1=P1.P1_START,
                                         p2=P2.P2_LAST,
                                         data=challenge_data) as response:
            yield response

    def seed_id_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response
