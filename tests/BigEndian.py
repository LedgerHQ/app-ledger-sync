import struct


class BigEndian:
    @staticmethod
    def shortToArray(n: int) -> bytearray:
        array = bytearray(2)
        struct.pack_into(">H", array, 0, n)
        return array

    @staticmethod
    def arrayToShort(array: bytearray) -> int:
        return struct.unpack_from(">H", array)[0]

    @staticmethod
    def numberToArray(n: int) -> bytearray:
        array = bytearray(4)
        struct.pack_into(">I", array, 0, n)
        return array

    @staticmethod
    def arrayToNumber(array: bytearray) -> int:
        return struct.unpack_from(">I", array)[0]
