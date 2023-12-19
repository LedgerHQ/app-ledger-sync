from CommandBlock import CommandBlock, Command, CommandType, commands
from CommandStreamEncoder import TLVTypes
from BigEndian import BigEndian


class TLV:
    class TLVField:
        def __init__(self, type, value):
            self.type = type
            self.value = value

    # Takes two bytearrays and concatenates them
    @staticmethod
    def push(a: bytearray, b: bytearray) -> bytearray:
        c = bytearray(len(a) + len(b))
        c[:len(a)] = a
        c[len(a):] = b
        return c

    @staticmethod
    def read_tlv(buffer, offset):
        type = buffer[offset]
        offset += 1
        length = buffer[offset]
        offset += 1
        value = buffer[offset:offset+length]
        offset += length
        return {'tlv': {'type': type, 'value': value}, 'offset': offset}
        # The offset is important as it indicates when the next TLV Field begins if there is any

    @staticmethod
    def read_all_tlv(buffer, offset):
        result = []

        while offset < len(buffer):
            tlv = TLV.read_tlv(buffer, offset)
            offset = tlv['offset']
            result.append(tlv['tlv'])

        return result
        # Returns final list of results where each element of the list is dictionary in TLV form with a type and value

    @staticmethod
    def readVarInt(read):
        if read['tlv']['type'] != TLVTypes.VarInt:
            raise ValueError(
                f"Invalid type for var int (at offset {read['offset'] - 2 - len(read['tlv']['value'])})")

        fill = 4 - len(read['tlv']['value'])
        normalized = TLV.push(bytearray([0, 0, 0, 0][:fill]), read['tlv']['value'])
        value = BigEndian.arrayToNumber(normalized)

        return {'value': value, 'offset': read['offset']}

    @staticmethod
    def read_bytes(read):
        if read['tlv']['type'] != TLVTypes.Bytes:
            raise ValueError(
                f"Invalid type for bytes (at offset {read['offset'] - 2 - len(read['tlv']['value'])})")

        value = read['tlv']['value']
        return {'value': value, 'offset': read['offset']}

    @staticmethod
    def read_string(read):
        if read['tlv']['type'] != TLVTypes.String:
            raise ValueError(
                f"Invalid type for string (at offset {read['offset'] - 2 - len(read['tlv']['value'])})")

        value = read['tlv']['value'].decode()
        return {'value': value, 'offset': read['offset']}

    @staticmethod
    def read_hash(read):
        if read['tlv']['type'] != TLVTypes.Hash:
            raise ValueError(
                f"Invalid type for hash (at offset {read['offset'] - 2 - len(read['tlv']['value'])})")

        value = read['tlv']['value']
        return {'value': value, 'offset': read['offset']}

    @staticmethod
    def read_signature(read):
        if read['tlv']['type'] != TLVTypes.Signature:
            raise ValueError(
                f"Invalid type for signature (at offset {read['offset'] - 2 - len(read['tlv']['value'])})")

        value = read['tlv']['value']
        return {'value': value, 'offset': read['offset']}

    @staticmethod
    def read_public_key(read):
        if read['tlv']['type'] != TLVTypes.PublicKey:
            raise ValueError(
                f"Invalid type for public key (at offset {read['offset'] - 2 - len(read['tlv']['value'])})")

        value = read['tlv']['value']
        return {'value': value, 'offset': read['offset']}

    @staticmethod
    def read_derivation_path(read):
        bytes_result = TLV.read_bytes(read)
        view = memoryview(bytes_result["value"]).cast("B")
        value = []

        for offset in range(0, len(bytes_result["value"]), 4):
            value.append(int.from_bytes(view[offset:offset+4], byteorder="big", signed=False))

        return {"value": value, "offset": bytes_result["offset"]}

    @staticmethod
    def read_null_or(read, func):
        if read['tlv']['type'] == TLVTypes.Null:
            return {'value': None, 'offset': read['offset']}
        return func(read)

    @staticmethod
    def read_command(tlv):
        command_type = tlv['type']
        if command_type == CommandType.Seed:
            return TLV.read_seed_command(tlv['value'])
        # elif command_type == CommandType.Derive:
            # return TLV.read_derive_command(tlv['value'])
        elif command_type == CommandType.AddMember:
            return TLV.read_add_member_command(tlv['value'])
        elif command_type == CommandType.PublishKey:
            return TLV.read_publish_key_command(tlv['value'])
        # elif command_type == CommandType.EditMember:
            # return read_edit_member_command(tlv['value'])
        elif command_type == CommandType.CloseStream:
            return TLV.read_close_stream_command(tlv['value'])
        else:
            raise ValueError("Unknown command type")

    @staticmethod
    def read_seed_command(buffer):
        read_topic = TLV.read_null_or(TLV.read_tlv(buffer, 0), TLV.read_bytes)
        read_protocol_version = TLV.readVarInt(TLV.read_tlv(buffer, read_topic['offset']))
        read_group_key = TLV.read_public_key(TLV.read_tlv(buffer, read_protocol_version['offset']))
        read_iv = TLV.read_bytes(TLV.read_tlv(buffer, read_group_key['offset']))
        read_encrypted_xpriv = TLV.read_bytes(TLV.read_tlv(buffer, read_iv['offset']))
        read_ephemeral_public_key = TLV.read_public_key(
            TLV.read_tlv(buffer, read_encrypted_xpriv['offset']))
        return commands.Seed(read_topic['value'],
                             read_protocol_version['value'],
                             read_group_key['value'],
                             read_iv['value'],
                             read_encrypted_xpriv['value'],
                             read_ephemeral_public_key['value'])

    @staticmethod
    def read_derive_command(buffer):
        read_path = TLV.read_derivation_path(TLV.read_tlv(buffer, 0))
        read_group_key = TLV.read_public_key(TLV.read_tlv(buffer, read_path['offset']))
        read_iv = TLV.read_bytes(TLV.read_tlv(buffer, read_group_key['offset']))
        read_encrypted_xpriv = TLV.read_bytes(TLV.mroread_tlv(buffer, read_iv['offset']))
        read_ephemeral_public_key = TLV.read_bytes(
            TLV.read_tlv(buffer, read_encrypted_xpriv['offset']))
        return commands.Derive(read_path['value'],
                               read_group_key['value'],
                               read_iv['value'],
                               read_encrypted_xpriv['value'],
                               read_ephemeral_public_key['value'])

    @staticmethod
    def read_add_member_command(buffer):
        read_name = TLV.read_string(TLV.read_tlv(buffer, 0))
        pubkey = TLV.read_public_key(TLV.read_tlv(buffer, read_name['offset']))
        permissions = TLV.readVarInt(TLV.read_tlv(buffer, pubkey['offset']))
        return commands.AddMember(read_name['value'], pubkey['value'], permissions['value'])

    @staticmethod
    def read_publish_key_command(buffer):
        IV = TLV.read_bytes(TLV.read_tlv(buffer, 0))
        encrypted_xpriv = TLV.read_bytes(TLV.read_tlv(buffer, IV['offset']))
        recipient = TLV.read_public_key(TLV.read_tlv(buffer, encrypted_xpriv['offset']))
        ephemeral_public_key = TLV.read_public_key(TLV.read_tlv(buffer, recipient['offset']))

        return commands.PublishKey(IV['value'], encrypted_xpriv['value'], recipient['value'], ephemeral_public_key['value'])

    @staticmethod
    def read_close_stream_command(buffer):
        return commands.CloseStream()


def unpack(buffer):
    stream = []
    offset = 0

    while offset < len(buffer):
        version = TLV.readVarInt(TLV.read_tlv(buffer, offset))
        parent = TLV.read_hash(TLV.read_tlv(buffer, version['offset']))
        issuer = TLV.read_public_key(TLV.read_tlv(buffer, parent['offset']))
        length = TLV.readVarInt(TLV.read_tlv(buffer, issuer['offset']))
        offset = length['offset']

        commands = []
        for _ in range(length['value']):
            commandBuffer = TLV.read_tlv(buffer, offset)
            command = TLV.read_command(commandBuffer['tlv'])
            commands.append(command)
            offset = commandBuffer['offset']

        signature = TLV.read_signature(TLV.read_tlv(buffer, offset))
        offset = signature['offset']
        stream.append(CommandBlock(version['value'], parent['value'],
                      issuer['value'], commands, signature['value']))

    return stream


class CommandStreamDecoder:
    @staticmethod
    def decode(buffer):
        return unpack(buffer)


'''
a = TLV.read_tlv(b'\x01\x01\xff', 0)
b = TLV.readVarInt(a)
print(b)
'''
