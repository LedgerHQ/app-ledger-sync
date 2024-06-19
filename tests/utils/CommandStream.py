from typing import Callable, List, Optional

from utils.CommandBlock import commands, hash_command_block, create_command_block, CommandType, Command, CommandBlock
from utils.CommandStreamResolver import CommandStreamResolver
from utils.NobleCrypto import DerivationPath
from utils.Device import device
from utils.InterfaceStreamTree import InterfaceStreamTree


ISSUER_PLACEHOLDER = bytearray([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
EMPTY = bytearray()


class CommandStream:
    def __init__(self, blocks: Optional[List[CommandBlock]] = None):
        if blocks is None:
            blocks = []
        self._blocks = blocks

    def get_blocks(self) -> list[CommandBlock]:
        return self._blocks

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
        if first_command_type == CommandType.Derive:
            return DerivationPath.to_string(self._blocks[0].commands[0].path)
        raise ValueError("Malformed CommandStream")

    def issue(self, dev: device, cmds: List[Command], tree=None, parentHash=None):
        if not tree:
            tree = None
        if not parentHash:
            parentHash = None

        lastBlockHash = hash_command_block(self._blocks[-1]) if len(self._blocks) > 0 else None
        block = create_command_block(ISSUER_PLACEHOLDER, cmds,
                                     bytearray(), parentHash or lastBlockHash)

        return self.push(block, dev, tree)

    def push(self, block: CommandBlock, issuer: device, tree: InterfaceStreamTree):
        stream = []

        if len(block.commands) == 0:
            raise ValueError("Attempts to create an empty block")

        if (len(self._blocks) == 0 or self._blocks[0].commands[0].get_type() != CommandType.Seed) and \
            block.commands[0].get_type() != CommandType.Seed:

            root = tree.get_root() if tree is not None else None
            if not root or len(root.get_blocks()) == 0:
                raise ValueError("Null or empty tree cannot be used to sign the new block")
            stream = [root.get_blocks()[0]] + self._blocks
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


class CommandStreamIssuer:
    def __init__(self, stream: CommandStream):
        self._stream: CommandStream = stream
        self._steps: List[Callable] = []

    def seed(self, topic=None):
        def step():
            return [commands.Seed(topic, 0, EMPTY, EMPTY, EMPTY, EMPTY)]

        self._steps.append(step)
        return self

    def derive(self, path):
        def step():
            derivation_path = DerivationPath.to_index_array(path)
            return [commands.Derive(derivation_path, EMPTY, EMPTY, EMPTY, EMPTY)]

        self._steps.append(step)
        return self

    def add_member(self, name, public_key, permissions, publish_key=True):
        def step():
            if publish_key:
                return [
                    commands.AddMember(name, public_key, permissions),
                    commands.PublishKey(EMPTY, EMPTY, public_key, EMPTY),
                ]
            return [commands.AddMember(name, public_key, permissions)]

        self._steps.append(step)
        return self

    def publish_key(self, public_key):
        def step():
            return [commands.PublishKey(EMPTY, EMPTY, public_key, EMPTY)]

        self._steps.append(step)
        return self

    def close(self):
        def step():
            return [commands.CloseStream()]

        self._steps.append(step)
        return self

    def issue(self, dev, stream_tree=None, parent_hash=None):
        # Calculate the hash of the last block in the stream, if available
        last_block_hash = hash_command_block(
            self._stream.get_blocks()[-1]) if self._stream.get_blocks() else None

        # print("Length stream" + repr(self._stream.get_blocks()))
        # Create a new block with the given or calculated parent hash
        block = create_command_block(ISSUER_PLACEHOLDER, [], bytearray(),
                                     parent_hash or last_block_hash)

        # Create a copy of the current command stream and a temporary stream with the new block
        stream = CommandStream(self._stream.get_blocks().copy())
        temp_stream = CommandStream(self._stream.get_blocks() + [block])

        cmds = []
        for step in self._steps:
            # Execute each step with the device, temporary stream, and stream tree
            new_commands = step()

            # Accumulate the new commands
            cmds.extend(new_commands)

            # Update the commands of the last block in the temporary stream
            temp_stream.get_blocks()[-1].commands = cmds

        # Issue the accumulated commands to the original stream
        return stream.issue(dev, cmds, stream_tree, parent_hash)
