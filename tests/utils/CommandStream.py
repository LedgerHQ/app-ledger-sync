from typing import List

from .CommandBlock import commands, hash_command_block, create_command_block, CommandType, Command, CommandBlock
from .CommandStreamResolver import CommandStreamResolver
from .NobleCrypto import Crypto, DerivationPath
from .Device import SodiumDevice, device
from .InterfaceStreamTree import InterfaceStreamTree


ISSUER_PLACEHOLDER = bytearray([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
EMPTY = bytearray()


class CommandStream:
    def __init__(self, blocks: List[CommandBlock] = None):
        if blocks is None:
            blocks = []
        self._blocks = blocks

    def edit(self):
        return CommandStreamIssuer(self)

    def get_root_hash(self):
        return hash_command_block(self._blocks[0])

    def resolve(self):
        return CommandStreamResolver.resolve(self._blocks)

    def get_stream_path(self):
        if len(self._blocks) == 0:
            return None

        first_command_type = self._blocks[0].commands[0].get_type()

        if first_command_type == CommandType.Seed:
            return ""

        elif first_command_type == CommandType.Derive:
            return DerivationPath.to_string(self._blocks[0].commands[0].path)
        else:
            raise ValueError("Malformed CommandStream")

    def issue(self, device: device, commands: List[Command], tree=None, parentHash=None):
        if not tree:
            tree = None
        if not parentHash:
            parentHash = None

        lastBlockHash = hash_command_block(self._blocks[-1]) if len(self._blocks) > 0 else None
        block = create_command_block(ISSUER_PLACEHOLDER, commands,
                                     bytearray(), parentHash or lastBlockHash)

        return self.push(block, device, tree)

    def push(self, block: CommandBlock, issuer: device, tree: InterfaceStreamTree):
        stream = []

        if len(block.commands) == 0:
            raise ValueError("Attempts to create an empty block")

        if (len(self._blocks) == 0 or self._blocks[0].commands[0].get_type() != CommandType.Seed) and block.commands[0].get_type() != CommandType.Seed:

            root = tree.get_root() if tree != None else None
            if not root or len(root._blocks) == 0:
                raise ValueError("Null or empty tree cannot be used to sign the new block")
            stream = [root._blocks[0]] + self._blocks
        else:
            stream = self._blocks.copy()

        if block.commands[0].get_type() == CommandType.Derive:
            b = block.copy()
            b.parent = hash_command_block(stream[0])
            stream.append(b)
        else:
            stream.append(block)

        signed_block = issuer.sign(stream, tree)  # Assuming issuer.sign() returns a signed block
        return CommandStream(self._blocks + [signed_block])

    '''
    def push(self, block:CommandBlock, issuer:device, tree = None): 
        #print(type(issuer))
        stream = []
     
        if len(block.commands) == 0:
            raise ValueError("Attempts to create an empty block")
        
        #UPDATE WITH TREE
        if (len(self._blocks) == 0 or self._blocks[0].commands[0].get_type() != CommandType.Seed) and block.commands[0].get_type() != CommandType.Seed:
            if tree is None:
                raise ValueError("Null tree cannot be used to sign the new block")
    
            #stream = self._blocks + [block]
        else:
            stream = self._blocks + [block]

        #print('Header')
        #print(repr(stream))

        signed_block = issuer.sign(stream, tree)
        return CommandStream(self._blocks + [signed_block])
    
    def resolve(self, incomplete=False):
        return CommandStreamResolver.resolve(self._blocks)
'''


class CommandStreamIssuer:
    def __init__(self, stream: CommandStream):
        self._stream = stream
        self._steps = []

    def seed(self, topic=None):
        def step(device, temp_stream, stream_tree=None):
            return [commands.Seed(topic, 0, EMPTY, EMPTY, EMPTY, EMPTY)]

        self._steps.append(step)
        return self

    def derive(self, path):
        def step(device, temp_stream, stream_tree=None):
            derivation_path = DerivationPath.to_index_array(path)
            return [commands.Derive(derivation_path, EMPTY, EMPTY, EMPTY, EMPTY)]

        self._steps.append(step)
        return self

    def add_member(self, name, public_key, permissions, publish_key=True):
        def step(device, temp_stream, stream_tree=None):
            if publish_key == True:
                return [
                    commands.AddMember(name, public_key, permissions),
                    commands.PublishKey(EMPTY, EMPTY, public_key, EMPTY),
                ]
            return [commands.AddMember(name, public_key, permissions)]

        self._steps.append(step)
        return self

    def publish_key(self, public_key):
        def step(device, temp_stream, stream_tree=None):
            return [commands.PublishKey(EMPTY, EMPTY, public_key, EMPTY)]

        self._steps.append(step)
        return self

    def close(self):
        def step(device, temp_stream, stream_tree=None):
            return [commands.CloseStream()]

        self._steps.append(step)
        return self

    def issue(self, device, stream_tree=None, parent_hash=None):
        # Calculate the hash of the last block in the stream, if available
        last_block_hash = hash_command_block(
            self._stream._blocks[-1]) if self._stream._blocks else None

        # print("Length stream" + repr(self._stream._blocks))
        # Create a new block with the given or calculated parent hash
        block = create_command_block(ISSUER_PLACEHOLDER, [], bytearray(),
                                     parent_hash or last_block_hash)

        # Create a copy of the current command stream and a temporary stream with the new block
        stream = CommandStream(self._stream._blocks.copy())
        temp_stream = CommandStream(self._stream._blocks + [block])

        commands = []
        for step in self._steps:
            # Execute each step with the device, temporary stream, and stream tree
            new_commands = step(device, temp_stream, stream_tree)

            # Accumulate the new commands
            commands.extend(new_commands)

            # Update the commands of the last block in the temporary stream
            temp_stream._blocks[-1].commands = commands

        # Issue the accumulated commands to the original stream
        return stream.issue(device, commands, stream_tree, parent_hash)
