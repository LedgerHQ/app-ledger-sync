from typing import cast
from utils.CommandBlock import CommandBlock, Command, CommandType, commands
from utils.BigEndian import BigEndian


# Combines the two byte arrays a and b
def push(a: bytearray, b: bytearray) -> bytearray:
    c = bytearray(len(a) + len(b))
    c[:len(a)] = a
    c[len(a):] = b
    return c

# Creates a TLV representation in a byte array


def pushTLV(a: bytearray, t: int, l: int, v: bytearray) -> bytearray:
    c = bytearray(len(a) + 2 + l)
    c[:len(a)] = a
    c[len(a):len(a)+2] = bytearray([t, l])
    c[len(a)+2:] = v
    return c


# Different TLV types
class TLVTypes:
    Null = 0
    VarInt = 1
    Hash = 2
    Signature = 3
    String = 4
    Bytes = 5
    PublicKey = 6

# Different methods to push a TLV Type to a string


class TLV:
    @staticmethod
    def pushString(a: bytearray, b: str) -> bytearray:
        encoded = b.encode()
        return pushTLV(a, TLVTypes.String, len(encoded), bytearray(encoded))

    @staticmethod
    def pushByte(a: bytearray, b: int) -> bytearray:
        return pushTLV(a, TLVTypes.VarInt, 1, bytearray([b]))

    @staticmethod
    def pushInt16(a: bytearray, b: int) -> bytearray:
        data = BigEndian.shortToArray(b)
        return pushTLV(a, TLVTypes.VarInt, 2, data)

    @staticmethod
    def pushInt32(a: bytearray, b: int) -> bytearray:
        data = BigEndian.numberToArray(b)
        return pushTLV(a, TLVTypes.VarInt, 4, data)

    @staticmethod
    def pushHash(a: bytearray, b: bytes) -> bytearray:
        return pushTLV(a, TLVTypes.Hash, len(b), bytearray(b))

    @staticmethod
    def pushSignature(a: bytearray, b: bytes) -> bytearray:
        return pushTLV(a, TLVTypes.Signature, len(b), bytearray(b))

    @staticmethod
    def pushBytes(a: bytearray, b: bytes) -> bytearray:
        return pushTLV(a, TLVTypes.Bytes, len(b), bytearray(b))

    @staticmethod
    def pushNull(a: bytearray) -> bytearray:
        return pushTLV(a, TLVTypes.Null, 0, bytearray())

    @staticmethod
    def pushPublicKey(a: bytearray, b: bytes) -> bytearray:
        return pushTLV(a, TLVTypes.PublicKey, len(b), bytearray(b))

    @staticmethod
    def pushDerivationPath(a: bytearray, b: list) -> bytearray:
        data = bytearray()
        for i in b:
            data = push(data, BigEndian.numberToArray(i))
        return TLV.pushBytes(a, data)

    # Methods to pack different commands into TLV format

    @staticmethod
    def packSeed(b: commands.Seed) -> bytearray:
        object_data = bytearray()
        if b.topic:
            object_data = TLV.pushBytes(object_data, b.topic)
        else:
            object_data = TLV.pushNull(object_data)
        object_data = TLV.pushInt16(object_data, b.protocol_version)
        object_data = TLV.pushPublicKey(object_data, b.group_key)
        object_data = TLV.pushBytes(object_data, b.initialization_vector)
        object_data = TLV.pushBytes(object_data, b.encrypted_xpriv)
        object_data = TLV.pushPublicKey(object_data, b.ephemeral_public_key)
        return object_data

    @staticmethod
    def packDerive(b: commands.Derive) -> bytearray:
        object_data = bytearray()
        object_data = TLV.pushDerivationPath(object_data, b.path)
        object_data = TLV.pushPublicKey(object_data, b.group_key)
        object_data = TLV.pushBytes(object_data, b.initialization_vector)
        object_data = TLV.pushBytes(object_data, b.encrypted_xpriv)
        object_data = TLV.pushPublicKey(object_data, b.ephemeral_public_key)
        return object_data

    @staticmethod
    def packAddMember(b: commands.AddMember) -> bytearray:
        object_data = bytearray()
        object_data = TLV.pushString(object_data, b.name)
        object_data = TLV.pushPublicKey(object_data, b.public_key)
        object_data = TLV.pushInt32(object_data, b.permissions)
        return object_data

    @staticmethod
    def packPublishKey(b: commands.PublishKey) -> bytearray:
        object_data = bytearray()
        object_data = TLV.pushBytes(object_data, b.initialization_vector)
        object_data = TLV.pushBytes(object_data, b.encrypted_xpriv)
        object_data = TLV.pushPublicKey(object_data, b.recipient)
        object_data = TLV.pushPublicKey(object_data, b.ephemeral_public_key)
        return object_data

    @staticmethod
    def packCloseStream() -> bytearray:
        return bytearray()


    @staticmethod
    def packCommand(buffer: bytearray, command: Command) -> bytearray:
        object_bytes = bytearray()
        command_type = command.get_type()

        if command_type == CommandType.Seed:
            command = cast(commands.Seed, command)
            object_bytes = TLV.packSeed(command)
        elif command_type == CommandType.Derive:
            command = cast(commands.Derive, command)
            object_bytes = TLV.packDerive(command)
        elif command_type == CommandType.AddMember:
            command = cast(commands.AddMember, command)
            object_bytes = TLV.packAddMember(command)
        elif command_type == CommandType.PublishKey:
            command = cast(commands.PublishKey, command)
            object_bytes = TLV.packPublishKey(command)
        elif command_type == CommandType.CloseStream:
            object_bytes = TLV.packCloseStream()
        # elif command_type == CommandType.EditMember:
        #     object_bytes = TLV.packEditMember(command)

        buffer = pushTLV(buffer, command.get_type(), len(object_bytes), object_bytes)
        return buffer

# Different methods to encode a whole command stream into TLV format


class CommandStreamEncoder:
    @staticmethod
    def encode(stream: list[CommandBlock]) -> bytearray:
        return pack(stream)

    @staticmethod
    def encodeBlockHeader(block: CommandBlock) -> bytearray:
        buffer = bytearray()
        buffer = TLV.pushByte(buffer, block.version)
        buffer = TLV.pushHash(buffer, block.parent)
        buffer = TLV.pushPublicKey(buffer, block.issuer)
        buffer = TLV.pushByte(buffer, len(block.commands))
        return buffer

    @staticmethod
    def encodeCommand(block: CommandBlock, index: int) -> bytearray:
        if index >= len(block.commands) or index < 0:
            raise IndexError("Index out of range")
        buffer = bytearray()
        buffer = TLV.packCommand(buffer, block.commands[index])
        return buffer

    @staticmethod
    def encodeSignature(block: CommandBlock) -> bytearray:
        if len(block.signature) == 0:
            return bytearray()
        return TLV.pushSignature(bytearray(), block.signature)


def pack(stream: list[CommandBlock]) -> bytearray:
    buffer = bytearray()
    for block in stream:
        buffer = push(buffer, CommandStreamEncoder.encodeBlockHeader(block))
        for index in range(len(block.commands)):
            buffer = push(buffer, CommandStreamEncoder.encodeCommand(block, index))
        buffer = push(buffer, CommandStreamEncoder.encodeSignature(block))
    return buffer

# Done Reviewing, only derivation path missing
