from indexedTree import IndexedTree
from NobleCrypto import DerivationPath
from InterfaceStreamTree import InterfaceStreamTree
from InterfaceStreamTree import PublishKeyEvent
from CommandStream import CommandStream


class ApplicationStreams:
    def __init__(self, appStream: CommandStream, appRootStream: CommandStream):
        self.appStream = appStream
        self.appRootStream = appRootStream


class StreamTreeCreateOpts:
    def __init__(self, topic=None):
        self.topic = topic if topic is not None else []


class StreamTree(InterfaceStreamTree):
    def __init__(self, tree: IndexedTree[CommandStream]):
        if tree.get_value() is None:
            raise ValueError("Root of the tree cannot be None")
        self.tree = tree

    def get_application_root_path(self, application_id: int) -> str:
        # TODO implement with key rotation (currently always returns on roots 0h)
        tree_root = "0h"  # TODO change this
        application_root = "0h"  # TODO change this
        return f"{tree_root}/{application_id}h/{application_root}"

    def get_publish_key_event(self, member: bytes, path: list) -> PublishKeyEvent or None:
        # Iterate over the tree from leaf to root
        leaf = self.tree.find_child(path)
        if not leaf or leaf.get_value() is None:
            if len(path) == 0:
                return None
            return self.get_publish_key_event(member, path[:-1])

        resolved = leaf.get_value().resolve()
        key = resolved.get_encrypted_key(member)
        if not key:
            if len(path) == 0:
                return None
            return self.get_publish_key_event(member, path[:-1])

        return PublishKeyEvent(
            stream=leaf.get_value(),
            encryptedXpriv=key.encryptedXpriv,
            ephemeralPublicKey=key.ephemeralPublicKey,
            nonce=key.initialiationVector,
            groupPublicKey=resolved.get_group_public_key()
        )

    def get_child(self, path):
        indexes = DerivationPath.to_index_array(path) if isinstance(path, str) else path
        subtree = self.tree.find_child(indexes)
        if subtree is None:
            return None
        return subtree.get_value()

    def get_root(self):
        return self.tree.get_value()

    def create_application_streams(self, owner, application_id):
        raise NotImplementedError("Not implemented")

    def share(self, path, owner, member, name, permission):
        indexes = path if isinstance(path, list) else DerivationPath.to_index_array(path)
        stream = self.get_child(indexes) or CommandStream()

        if len(stream.blocks) == 0 and len(indexes) > 0:
            root = self.get_root().get_root_hash()
            stream = stream.edit().derive(indexes).add_member(
                name, member, permission, True).issue(owner, self, root)
            return self.update(stream)
        elif len(stream.blocks) == 0:
            raise ValueError(
                "StreamTree.share cannot add a member if the root was not previously created")
        else:
            new_stream = stream.edit().add_member(name, member, permission).issue(owner, self)
            return self.update(new_stream)

    def update(self, stream: CommandStream):
        path = stream.get_stream_path()
        if path is None:
            raise ValueError("Stream path cannot be None")
        indexes = DerivationPath.to_index_array(path)
        new_tree = self.tree.update_child(indexes, stream)
        return StreamTree(new_tree)

    @staticmethod
    def create_new_tree(owner, opts={}):
        stream = CommandStream()
        stream = stream.edit().seed(opts.get('topic')).issue(owner)
        tree = IndexedTree(stream)
        return StreamTree(tree)

    @staticmethod
    def from_streams(*streams):
        stream_map = {}
        for stream in streams:
            path = stream.get_stream_path()
            if path is None:
                raise ValueError("Stream path cannot be None")
            stream_map[path] = stream

        root = stream_map.get('')
        if root is None:
            raise ValueError("StreamTree.from requires the root of the tree")
        tree = IndexedTree(root)
        stream_map.pop('')
        for path, stream in stream_map.items():
            p = DerivationPath.to_index_array(path)
            tree = tree.add_child(p, IndexedTree(stream))
        return StreamTree(tree)
