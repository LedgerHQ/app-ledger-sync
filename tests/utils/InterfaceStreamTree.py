from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .CommandStream import CommandStream


class PublishKeyEvent:
    def __init__(self, stream: 'CommandStream', encryptedXpriv, groupPublicKey, ephemeralPublicKey, nonce):
        self.stream = stream
        self.encryptedXpriv = encryptedXpriv
        self.groupPublicKey = groupPublicKey
        self.ephemeralPublicKey = ephemeralPublicKey
        self.nonce = nonce


class InterfaceStreamTree:
    def get_application_root_path(self, application_id: int) -> str:
        pass

    def get_publish_key_event(self, member: bytes, path: list) -> PublishKeyEvent or None:
        pass

    def get_child(self, path):
        pass

    def get_root(self):
        pass

    def create_application_streams(self, owner, application_id):
        pass

    def share(self, path, owner, member, name, permission):
        pass

    def update(self, stream):
        pass
