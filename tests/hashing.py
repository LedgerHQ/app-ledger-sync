

class NoHash:

    def __init__(self, buffer) -> None:
        from NobleCrypto import Crypto

        self.digest_size = 32
        self.block_size = 32
        self.name = 'NoHash'
        self.buffer = bytes() + buffer
        print('buffer' + Crypto.to_hex(buffer))

    def update(self, data):
        self.buffer += data

    def digest(self):
        from NobleCrypto import Crypto
        if len(self.buffer) > self.digest_size:
            raise ('NoHash can only hash data up to {self.digest_size}')

        print('Buffer:' + Crypto.to_hex(self.buffer))
        return self.buffer

    def hexdigest(self):
        from NobleCrypto import Crypto
        return Crypto.to_hex(self.digest())

    def copy(self):
        return NoHash(self.buffer)
