class SeedIdChallenge:
    STRUCTURE_TYPE = 0x01
    VERSION = 0x02
    CHALLENGE = 0x12
    SIGNER_ALGO = 0x14
    DER_SIGNATURE = 0x15
    VALID_UNTIL = 0x16
    TRUSTED_NAME = 0x20
    PUBLIC_KEY_CURVE = 0x32
    PUBLIC_KEY = 0x33
    PROTOCOL_VERSION = 0x60

    DEFAULT_VALUES = {
        STRUCTURE_TYPE: 0x07,
        VERSION: 0,
        CHALLENGE: b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10',
        SIGNER_ALGO: 0x01,
        DER_SIGNATURE: "0b3c6d9f2a5c8b1e4f7a0b3c6d9f2a5c8b1e4f7a0b3c6d9f2a5c8b1e4f7a0b3c6d9f2a5c8b1",
        VALID_UNTIL: 1636357581,
        TRUSTED_NAME: b'MyHost',
        PUBLIC_KEY_CURVE: 0x21,
        PUBLIC_KEY: b'\x01\x02\x03...\x10',
        PROTOCOL_VERSION: 0x00000001,
    }

    FIELD_LENGTHS = {
        STRUCTURE_TYPE: 1,
        VERSION: 1,
        CHALLENGE: 16,
        SIGNER_ALGO: 1,
        DER_SIGNATURE: None,  # Variable length
        VALID_UNTIL: 4,
        TRUSTED_NAME: None,  # Variable length, max 64
        PUBLIC_KEY_CURVE: 1,
        PUBLIC_KEY: 33,  # Variable length, 33 for EC public keys
        PROTOCOL_VERSION: 4,
    }

    FIELD_NAMES = {
        STRUCTURE_TYPE: 'payload_type',
        VERSION: 'version',
        CHALLENGE: 'challenge_data',
        SIGNER_ALGO: 'rp_credential_sign_algorithm',
        DER_SIGNATURE: 'rp_signature',
        VALID_UNTIL: 'challenge_expiry',
        TRUSTED_NAME: 'host',
        PUBLIC_KEY_CURVE: 'rp_credential_curve_id',
        PUBLIC_KEY: 'rp_credential_public_key',
        PROTOCOL_VERSION: 'protocol_version',
    }

    def __init__(self):
        self.payload_type = None
        self.version = None
        self.protocol_version = None
        self.challenge_data = None
        self.challenge_expiry = None
        self.host = None
        self.rp_credential_sign_algorithm = None
        self.rp_credential_curve_id = None
        self.rp_credential_public_key = None
        self.rp_signature = None

    def _serialize_field(self, tag_label, length, value):
        serialized_field = bytearray()
        serialized_field.append(tag_label)

        if value is not None:
            if isinstance(value, int):
                # Convert integer value to bytes
                value = value.to_bytes(length, 'big')
            elif isinstance(value, str):
                # Convert string value to bytes
                value = value.encode('utf-8')[length:]

            serialized_field.append(len(value))

            serialized_field.extend(value)

        return serialized_field

    def to_tlv(self):
        tlv_data = bytearray()

        for tag_label, length in self.FIELD_LENGTHS.items():
            value = getattr(self, self.FIELD_NAMES[tag_label])
            if value is not None:
                tlv_data.extend(self._serialize_field(tag_label, length, value))

        return bytes(tlv_data)

    @staticmethod
    def find_field(serialized_data, tag_label):
        index = 0
        length = 0

        while index < len(serialized_data):
            current_tag = serialized_data[index]
            current_length = serialized_data[index + 1]

            print(current_tag, "/", tag_label)
            if current_tag == tag_label:
                return index, current_length

            index += current_length + 2

        index = -1
        return index, length

    @staticmethod
    def print_field(serialized_data):
        index = 0

        while index < len(serialized_data):
            current_tag = serialized_data[index]
            print(current_tag)
            tag_name = SeedIdChallenge.FIELD_NAMES[current_tag]
            current_length = serialized_data[index + 1]
            value = serialized_data[index + 2:index + 2 + current_length]

            print(hex(current_tag), "")

            print(f"{tag_name}({current_length}): {value.hex()}")

            index += current_length + 2

    @staticmethod
    def update_field(serialized_data, tag_label, new_value, new_length=None):
        index, current_length = SeedIdChallenge.find_field(serialized_data, tag_label)

        if index != -1:
            # Create the updated TLV field
            updated_field = bytearray()
            updated_field.append(tag_label)
            updated_field.append(current_length if new_length is None else new_length)
            if isinstance(new_value, int):
                # Convert integer value to bytes
                new_value = new_value.to_bytes(SeedIdChallenge.FIELD_LENGTHS[tag_label], 'big')
            elif isinstance(new_value, str):
                # Convert string new_value to bytes
                new_value = new_value.encode('utf-8')
            updated_field.extend(new_value)

            # Replace the old TLV field with the updated one
            serialized_data = serialized_data[:index] + updated_field + \
                serialized_data[index + current_length + 2:]

        return serialized_data
