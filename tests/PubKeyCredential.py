class PubKeyCredential:
    def __init__(self, version, curve_id, sign_algorithm, public_key):
        self.version = version
        self.curve_id = curve_id
        self.sign_algorithm = sign_algorithm
        self.public_key = public_key

    def to_bytes(self):
        # Convert the fields to bytes and concatenate them
        version_bytes = bytes([self.version])
        curve_id_bytes = bytes([self.curve_id])
        sign_algorithm_bytes = bytes([self.sign_algorithm])
        public_key_length_bytes = bytes([len(self.public_key)])
        public_key_bytes = bytes(self.public_key)

        return version_bytes + curve_id_bytes + sign_algorithm_bytes + public_key_length_bytes + public_key_bytes

    @classmethod
    def from_bytes(cls, data, offset=0):
        # Parse the bytes to create an instance of PubKeyCredential
        version = data[0 + offset]
        curve_id = data[1 + offset]
        sign_algorithm = data[2 + offset]
        public_key_length = data[3 + offset]
        public_key = data[4 + offset:4 + offset + public_key_length]

        return cls(version, curve_id, sign_algorithm, public_key), 4 + public_key_length

    def assert_validity(self):
        if self.version != 0x00:
            print(f"Wrong version: {self.version}")
            return False
        if self.curve_id != 0x21:
            print(f"Wrong curve id: {self.curve_id}")
            return False
        if self.sign_algorithm != 0x01:
            print(f"Wrong sign algorithm: {self.sign_algorithm}")
            return False
        if len(self.public_key) != 0x21:
            print(f"Wrong pubkey len: {len(self.public_key)}")
            return False
        return True

    def __str__(self):
        return (
            "PubkeyCredential:\n"
            f"Version: 0x{self.version:02X}\n"
            f"Curve ID: 0x{self.curve_id:02X}\n"
            f"Sign Algorithm: 0x{self.sign_algorithm:02X}\n"
            f"Public Key Length: 0x{len(self.public_key):02X}\n"
            f"Public Key: 0x{''.join([f'{byte:02X}' for byte in self.public_key])}"
        )
