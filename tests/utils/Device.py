from typing import List, cast

from utils.NobleCrypto import Crypto
from utils.CommandBlock import CommandType, sign_command_block, CommandBlock, commands
from utils.CommandStreamResolver import CommandStreamResolver


class device:
    def get_public_key(self) -> bytes:
        raise NotImplementedError

    def sign(self, stream, tree=None) -> CommandBlock:
        raise NotImplementedError

    def read_key(self, tree, path) -> bytes:
        raise NotImplementedError

    def derive_key(self, tree, path) -> bytes:
        raise NotImplementedError


class SodiumDevice(device):
    def __init__(self, kp):
        self.key_pair = kp

    def read_key(self, tree, path) -> bytes:
        event = tree.get_publish_key_event(self.get_public_key(), path)
        if event is None:
            raise ValueError("Cannot find the key publication event")
        shared_key = self.decrypt_shared_key({
            'encryptedXpriv': event.encryptedXpriv,
            'initializationVector': event.nonce,
            'publicKey': event.groupPublicKey,
            'ephemeralPublicKey': event.ephemeralPublicKey
        })
        index = len(event.stream.get_stream_path())
        while index < len(path):
            derivation = self.derive_key(event.stream, path[:index])
            shared_key['xpriv'] = derivation['xpriv'] # type:ignore
            shared_key['publicKey'] = derivation['publicKey'] # type:ignore
            index += 1
        return cast(bytes, shared_key['xpriv'])

    def derive_key(self, tree, path) -> bytes:
        raise NotImplementedError

    def get_public_key(self):
        return self.key_pair['publicKey']

    def generateSharedKey(self):
        xpriv = Crypto.random_bytes(64)
        pk = Crypto.derive_private(xpriv, [])
        return {'xpriv': xpriv, 'publicKey': pk['publicKey']}

    def encrypt_shared_key(self, shared_key, recipient):
        kp = Crypto.randomKeyPair()
        secret = Crypto.ecdh(kp, recipient)
        initialization_vector = Crypto.random_bytes(16)
        encrypted_xpriv = Crypto.encrypt(secret, initialization_vector, shared_key['xpriv'])
        return {'encryptedXpriv': encrypted_xpriv,
                'publicKey': shared_key['publicKey'],
                'ephemeralPublicKey': kp['publicKey'],
                'initializationVector': initialization_vector}

    def decrypt_shared_key(self, encrypted_shared_key):
        ecdh = Crypto.ecdh(self.key_pair, encrypted_shared_key['ephemeralPublicKey'])
        xpriv = Crypto.decrypt(
            ecdh, encrypted_shared_key['initializationVector'], encrypted_shared_key['encryptedXpriv'])
        return {'xpriv': xpriv, 'publicKey': encrypted_shared_key['publicKey']}

    def sign(self, stream: List[CommandBlock], tree=None):
        if len(stream) == 0:
            raise ValueError("Cannot sign an empty stream")
        if len(stream[-1].commands) == 0:
            raise ValueError("Cannot sign an empty block")
        last_block = stream[-1]

        last_block.issuer = self.key_pair['publicKey']

        # Resolve the stream (before the last block)
        # Resolved returns a ResolvedCommandStreamInternals Class Object

        resolved = CommandStreamResolver.resolve(stream[:-1])

        shared_key = None

        # Iterate through the commands to inject encrypted keys
        seedCount = 0
        added_members = []
        # for command_index in range(len(last_block.commands)):
        for command_index, _ in enumerate(last_block.commands):
            command = last_block.commands[command_index]
            command_type = command.get_type()

            if command_type == CommandType.Seed:
                if len(stream) > 1 and stream[0].commands[0].get_type() == CommandType.Seed:
                    raise ValueError('SEED ALREADY CREATED IN STREAM')
                if seedCount == 0:
                    command = cast(commands.Seed, command)
                    shared_key = self.generateSharedKey()
                    encrypted_shared_key = self.encrypt_shared_key(shared_key, self.key_pair['publicKey'])
                    if shared_key:
                        command.group_key = shared_key['publicKey']
                    command.encrypted_xpriv = encrypted_shared_key['encryptedXpriv']
                    command.ephemeral_public_key = encrypted_shared_key['ephemeralPublicKey']
                    command.initialization_vector = encrypted_shared_key['initializationVector']

                if seedCount == 1:
                    raise ValueError('SEED ALREADY CREATED IN BLOCK')

                seedCount += 1

            elif command_type == CommandType.Derive:
                command = cast(commands.Derive, command)
                if not tree:
                    raise ValueError("Cannot derive a key without a tree")
                shared_key =   super().derive_key(tree, command.path)
                encrypted_derived_key = self.encrypt_shared_key(shared_key, self.key_pair['publicKey'])
                if shared_key:
                    command.group_key = shared_key['publicKey'] # type:ignore
                command.encrypted_xpriv = encrypted_derived_key['encryptedXpriv'] # type:ignore
                command.initialization_vector = encrypted_derived_key['initializationVector'] # type:ignore
                command.ephemeral_public_key = encrypted_derived_key['ephemeralPublicKey'] # type:ignore

            elif command_type == CommandType.PublishKey:
                command = cast(commands.PublishKey, command)
                is_added_in_current_block = Crypto.to_hex(command.recipient) in added_members
                if Crypto.to_hex(command.recipient) not in resolved.get_members() and not is_added_in_current_block:
                    raise ValueError('Recipient is not part of the trustchain')
                if not shared_key:
                    encrypted_key = resolved.get_encrypted_key(self.key_pair['publicKey'])
                    if encrypted_key:
                        shared_key = self.decrypt_shared_key({
                            'encryptedXpriv': encrypted_key['encryptedXpriv'], # type:ignore
                            'initializationVector': encrypted_key['initializationVector'], # type:ignore
                            'publicKey': encrypted_key['issuer'], # type:ignore
                            'ephemeralPublicKey': encrypted_key['ephemeralPublicKey'] # type:ignore
                        })

                    elif stream[0].commands[0].get_type() == CommandType.Seed:
                        if Crypto.to_hex(stream[0].issuer) != Crypto.to_hex(self.key_pair['publicKey']):
                            raise ValueError("Cannot read the seed key from another device")
                    else:
                        shared_key = super().derive_key(tree, resolved.get_stream_derivation_path())
                    if not shared_key:
                        raise ValueError("Cannot find the shared key")

                encrypted_shared_key = self.encrypt_shared_key(shared_key, command.recipient)
                command.encrypted_xpriv = encrypted_shared_key['encryptedXpriv'] # type:ignore
                command.initialization_vector = encrypted_shared_key['initializationVector'] # type:ignore
                command.ephemeral_public_key = encrypted_shared_key['ephemeralPublicKey'] # type:ignore
            elif command_type == CommandType.AddMember:
                command = cast(commands.AddMember, command)
                added_members.append(Crypto.to_hex(command.public_key))

        signature = sign_command_block(last_block, self.key_pair['privateKey']).signature
        last_block.signature = signature
        return last_block


def createDevice():
    keyPair = Crypto.randomKeyPair()
    return SodiumDevice(keyPair)
