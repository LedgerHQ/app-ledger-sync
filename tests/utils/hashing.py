
from utils.NobleCrypto import Crypto

class NoHash:

    def __init__(self, buffer: bytes) -> None:
        self.digest_size = 32
        self.block_size = 32
        self.name = 'NoHash'
        self.buffer = bytes() + buffer

    def update(self, data) -> None:
        self.buffer += data

    def digest(self):
        if len(self.buffer) > self.digest_size:
            raise ValueError(f"NoHash can only hash data up to {self.digest_size}")
        return self.buffer

    def hexdigest(self) -> str:
        return Crypto.to_hex(self.digest())

    def copy(self):
        return NoHash(self.buffer)
