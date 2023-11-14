from typing import List, Union
import secrets
import hashlib
import copy
from .NobleCrypto import Crypto, DerivationPath


class Command:
    def get_type(self):
        pass


class CommandType:
    Seed = 0x10
    AddMember = 0x11
    PublishKey = 0x12
    CloseStream = 0x13
    EditMember = 0x14
    Derive = 0x15


class Permissions:
    KEY_READER = 0x01
    KEY_CREATOR = 0x02
    KEY_REVOKER = 0x04
    ADD_MEMBER = 0x08
    REMOVE_MEMBER = 0x16
    CHANGE_MEMBER_PERMISSIONS = 0x32
    CHANGE_MEMBER_NAME = 0x64
    OWNER = 0xFFFFFFFF


class commands:
    class Seed(Command):
        def __init__(self, topic: Union[bytes, None], protocol_version: int, group_key: bytes, initialization_vector: bytes, encrypted_xpriv: bytes, ephemeral_public_key: bytes):
            self.topic = topic
            self.protocol_version = protocol_version
            self.group_key = bytes([0] * 33) if len(group_key) == 0 else group_key
            self.initialization_vector = bytes(
                [0] * 16) if len(initialization_vector) == 0 else initialization_vector
            self.encrypted_xpriv = bytes([0] * 64) if len(encrypted_xpriv) == 0 else encrypted_xpriv
            self.ephemeral_public_key = bytes(
                [0] * 33) if len(ephemeral_public_key) == 0 else ephemeral_public_key

        def get_type(self):
            return CommandType.Seed

        def __eq__(self, other):
            a = self.topic == other.topic
            b = self.protocol_version == other.protocol_version
            c = self.group_key == other.group_key
            d = self.initialization_vector == other.initialization_vector
            e = self.encrypted_xpriv == other.encrypted_xpriv
            f = self.ephemeral_public_key == other.ephemeral_public_key

            return (a and b and c and d and e and f)

        def __repr__(self):
            return f'<Seed topic: {Crypto.to_repr(self.topic)} protVersion: {Crypto.to_repr(self.protocol_version)} groupKey: {Crypto.to_repr(self.group_key)} iv: {Crypto.to_repr(self.initialization_vector)} xpriv: {Crypto.to_repr(self.encrypted_xpriv)} ephPublicKey: {Crypto.to_repr(self.ephemeral_public_key)}>'

        def copy(self):
            return commands.Seed(self.topic, self.protocol_version, self.group_key, self.initialization_vector, self.encrypted_xpriv, self.ephemeral_public_key)

    class Derive(Command):
        def __init__(self, path: List[int], group_key: bytes, initialization_vector: bytes, encrypted_xpriv: bytes, ephemeral_public_key: bytes):
            self.path = path
            self.group_key = group_key
            self.initialization_vector = initialization_vector
            self.encrypted_xpriv = encrypted_xpriv
            self.ephemeral_public_key = ephemeral_public_key

        def get_type(self):
            return CommandType.Derive

        def __eq__(self, other):
            a = self.path == other.path
            b = self.group_key == other.group_key
            c = self.initialization_vector == other.initialization_vector
            d = self.encrypted_xpriv == other.encrypted_xpriv
            e = self.ephemeral_public_key == other.ephemeral_public_key

            return (a and b and c and d and e)

        def __repr__(self):
            return f'<Derive path: {DerivationPath.to_string(self.path)} groupKey: {Crypto.to_repr(self.group_key)} iv: {Crypto.to_repr(self.initialization_vector)} xpriv: {Crypto.to_repr(self.encrypted_xpriv)} ephPublicKey: {Crypto.to_repr(self.ephemeral_public_key)}>'

        def copy(self):
            return commands.Derive(self.path.copy(), self.group_key, self.initialization_vector, self.encrypted_xpriv, self.ephemeral_public_key)

    class AddMember(Command):
        def __init__(self, name: str, public_key: bytes, permissions: int):
            self.name = name
            self.public_key = public_key
            self.permissions = permissions

        def get_type(self):
            return CommandType.AddMember

        def __eq__(self, other):
            a = self.name == other.name
            b = self.public_key == other.public_key
            c = self.permissions == other.permissions

        def __repr__(self):
            return f'<AddMember name: {self.name} publicKey: {Crypto.to_repr(self.public_key)} permissions: {self.permissions}>'

        def copy(self):
            return commands.AddMember(self.name, self.public_key, self.permissions)

    class PublishKey(Command):
        def __init__(self, initialization_vector: bytes, encrypted_xpriv: bytes, recipient: bytes, ephemeral_public_key: bytes):
            self.initialization_vector = initialization_vector
            self.encrypted_xpriv = encrypted_xpriv
            self.recipient = recipient
            self.ephemeral_public_key = ephemeral_public_key

        def get_type(self):
            return CommandType.PublishKey

        def __eq__(self, other):
            a = self.initialization_vector == other.initialization_vector
            b = self.encrypted_xpriv == other.encrypted_xpriv
            c = self.recipient == other.recipient
            d = self.ephemeral_public_key == other.ephemeral_public_key

            return (a and b and c and d)

        def copy(self):
            return commands.PublishKey(self.initialization_vector, self.encrypted_xpriv, self.recipient, self.ephemeral_public_key)

        def __repr__(self):
            return f'<PublishKey iv: {Crypto.to_repr(self.initialization_vector)}  xpriv: {Crypto.to_repr(self.encrypted_xpriv)} recipient: {Crypto.to_repr(self.recipient)} ephPublicKey: {Crypto.to_repr(self.ephemeral_public_key)}>'

    class CloseStream(Command):
        def __init__(self):
            pass

        def get_type(self):
            return CommandType.CloseStream

        def __repr__(self) -> str:
            return f'<CloseStream>'

        def copy(self):
            return commands.CloseStream()


class CommandBlock:
    def __init__(self, version: int, parent: bytes, issuer: bytes, commands: List[Command], signature: bytes):
        self.version = version
        self.parent = parent
        self.issuer = issuer
        self.commands = commands
        self.signature = signature

    def __eq__(self, other):
        a = self.version == other.version
        b = self.parent == other.parent
        c = self.issuer == other.issuer
        d = self.commands == other.commands
        e = self.signature == other.signature

        return (a and b and c and e)

    def copy(self):
        block = CommandBlock(self.version, self.parent, self.issuer,
                             self.commands.copy(), self.signature)
        return block

    def __repr__(self):
        string = f'<CommandBlock version: {self.version} , parent: {Crypto.to_repr(self.parent)}, issuer: {Crypto.to_repr(self.issuer)}, signature:{Crypto.to_array(self.signature)}>'

        for command in self.commands:
            string += '\n' + repr(command)

        return string


def create_command_block(issuer: bytes, commands: List[Command], signature: bytes = bytes(), parent: Union[bytes, None] = None):
    if parent is None:
        parent = Crypto.random_bytes(32)

    return CommandBlock(1, parent, issuer, commands, signature)


def sign_command_block(block: CommandBlock, issuer: bytes, secret_key: bytes):
    signature = Crypto.sign(hash_command_block(block), Crypto.keyPair_from_secret_key(secret_key))
    copyBlock = block
    copyBlock.signature = signature
    return copyBlock


def hash_command_block(block: CommandBlock):
    # Import in function
    from .CommandStreamEncoder import CommandStreamEncoder

    return Crypto.hash(CommandStreamEncoder.encode([block]))
    # return hashlib.sha256(CommandStreamEncoder.encode([block])).digest()


def verify_command_block(block: CommandBlock):
    unsigned_block = block.copy()
    unsigned_block.signature = bytearray()

    hash = hash_command_block(unsigned_block)

    return Crypto.verify(hash, block.signature, bytes(block.issuer))
