from NobleCrypto import Crypto
from CommandBlock import Permissions, hash_command_block, CommandType, verify_command_block, CommandBlock, Command, commands
from typing import List, cast


class ResolvedCommandStreamInternals:
    def __init__(self):
        self.is_created = False
        self.members = []
        self.topic = None
        self.keys = {}
        self.permission = {}
        self.height = 0
        self.stream_id = ""
        self.hashes = []
        self.names = {}
        self.group_public_key = bytearray()
        self.derivation_path = []


class CommandStreamResolver:
    @staticmethod
    def assert_issuer_can_publish(issuer, internals: ResolvedCommandStreamInternals):
        if issuer not in internals.members:
            raise ValueError(f"Issuer is not a member of the group at height {internals.height}")
        if internals.permission[Crypto.to_hex(issuer)] & 0x02 == Permissions.KEY_READER:
            raise ValueError(
                f"Issuer does not have permission to publish keys at height {internals.height}")
        if internals.keys.get(Crypto.to_hex(issuer)) is None and internals.permission[Crypto.to_hex(issuer)] & Permissions.KEY_CREATOR != Permissions.KEY_CREATOR:
            raise ValueError(f"Issuer does not have a key to publish at height {internals.height}")
        if Crypto.to_hex(issuer) not in internals.keys and internals.permission[Crypto.to_hex(issuer)] & Permissions.KEY_CREATOR != Permissions.KEY_CREATOR and len(internals.keys.keys()) > 0:
            raise ValueError(f"Issuer is trying to publish a new key at height {internals.height}")

    @staticmethod
    def assert_issuer_can_add_member(issuer, internals: ResolvedCommandStreamInternals):
        if issuer not in internals.members:
            raise ValueError(f"Issuer is not a member of the group at height {internals.height}")
        if internals.permission[Crypto.to_hex(issuer)] & Permissions.ADD_MEMBER != Permissions.ADD_MEMBER:
            raise ValueError(
                f"Issuer does not have permission to add members at height {internals.height}")

    @staticmethod
    def assert_stream_is_created(internals: ResolvedCommandStreamInternals):
        if not internals.is_created:
            raise ValueError(f"The stream is not created at height {internals.height}")

    @staticmethod
    def replay_command(command: Command, block: CommandBlock, block_hash, height, internals: ResolvedCommandStreamInternals):
        command_type = command.get_type()

        if command_type == CommandType.Seed:
            command = cast(commands.Seed, command)
            internals.is_created = True
            internals.topic = command.topic
            internals.members.append(block.issuer)
            internals.permission[Crypto.to_hex(block.issuer)] = Permissions.OWNER
            internals.stream_id = block_hash
            internals.keys[Crypto.to_hex(block.issuer)] = {
                "encryptedXpriv": command.encrypted_xpriv,
                "issuer": block.issuer,
                "ephemeralPublicKey": command.ephemeral_public_key,
                "initializationVector": command.initialization_vector
            }
            internals.group_public_key = command.group_key

        elif command_type == CommandType.Derive:
            command = cast(commands.Derive, command)
            internals.is_created = True
            internals.members.append(block.issuer)
            internals.permission[Crypto.to_hex(block.issuer)] = Permissions.OWNER
            internals.stream_id = block_hash
            internals.keys[Crypto.to_hex(block.issuer)] = {
                "encryptedXpriv": command.encrypted_xpriv,
                "ephemeralPublicKey": command.ephemeral_public_key,
                "initializationVector": command.initialization_vector,
                "issuer": block.issuer
            }
            internals.group_public_key = command.group_key
            internals.derivation_path = command.path

        elif command_type == CommandType.AddMember:
            command = cast(commands.AddMember, command)
            CommandStreamResolver.assert_stream_is_created(internals)
            CommandStreamResolver.assert_issuer_can_add_member(block.issuer, internals)
            internals.members.append(command.public_key)
            internals.permission[Crypto.to_hex(command.public_key)] = command.permissions
            internals.names[Crypto.to_hex(command.public_key)] = command.name

        elif command_type == CommandType.PublishKey:
            command = cast(commands.PublishKey, command)
            CommandStreamResolver.assert_stream_is_created(internals)
            CommandStreamResolver.assert_issuer_can_publish(block.issuer, internals)
            internals.keys[Crypto.to_hex(command.recipient)] = {
                "encryptedXpriv": command.encrypted_xpriv,
                "ephemeralPublicKey": command.ephemeral_public_key,
                "issuer": block.issuer,
                "initializationVector": command.initialization_vector
            }
        return internals

    @staticmethod
    def resolve_block(block: CommandBlock, height, internals: ResolvedCommandStreamInternals):
        # Check signature
        if not verify_command_block(block):
            raise ValueError(f"Invalid block signature at height {height}")

        # Check if issuer is part of the group
        if height > 0 and block.issuer not in internals.members:
            raise ValueError(f"Issuer is not part of the group at height {height}")

        block_hash = Crypto.to_hex(hash_command_block(block))

        for command in block.commands:
            internals = CommandStreamResolver.replay_command(
                command, block, block_hash, height, internals
            )

        internals.hashes.append(block_hash)
        return internals

    @staticmethod
    def resolve(stream: List[CommandBlock]):
        internals = ResolvedCommandStreamInternals()
        for height, block in enumerate(stream):
            internals.height = height
            if height > 0 and Crypto.to_hex(block.parent) != Crypto.to_hex(hash_command_block(stream[height - 1])):
                raise Exception(
                    "Command stream has been tampered with (invalid parent hash) at height " + str(height))
            if len(block.signature) == 0:
                break
            internals = CommandStreamResolver.resolve_block(block, height, internals)
        return ResolvedCommandStream(internals)


class ResolvedCommandStream:
    def __init__(self, internals: ResolvedCommandStreamInternals):
        self._internals = internals

    def is_created(self):
        return self._internals.is_created

    def get_members(self):
        return self._internals.members

    def get_topic(self):
        return self._internals.topic

    def is_owner(self, public_key):
        return self._internals.permission.get(Crypto.to_hex(public_key)) == Permissions.OWNER

    def is_key_creator(self, public_key):
        return (self._internals.permission.get(Crypto.to_hex(public_key)) & Permissions.KEY_CREATOR) == Permissions.KEY_CREATOR

    def owns_key(self, public_key):
        return self._internals.keys.get(Crypto.to_hex(public_key)) is not None

    def is_member_adder(self, public_key):
        return (self._internals.permission.get(Crypto.to_hex(public_key)) & Permissions.ADD_MEMBER) == Permissions.ADD_MEMBER

    def is_member_remover(self, public_key):
        return (self._internals.permission.get(Crypto.to_hex(public_key)) & Permissions.REMOVE_MEMBER) == Permissions.REMOVE_MEMBER

    def key_count(self):
        return len(self._internals.keys)

    def get_encrypted_key(self, public_key):
        key = self._internals.keys.get(Crypto.to_hex(public_key))
        return key if key else None

    def get_group_public_key(self):
        return self._internals.group_public_key

    def get_stream_derivation_path(self):
        return self._internals.derivation_path
