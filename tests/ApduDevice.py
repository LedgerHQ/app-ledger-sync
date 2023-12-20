from CommandStreamDecoder import TLV
from CommandBlock import CommandType, Command, CommandBlock, commands
from NobleCrypto import Crypto
from CommandStream import CommandStream
from ragger.backend.interface import BackendInterface
from typing import List, Union, cast
from Device import device


# from ragger.utils import pack_APDU, RAPDU, Crop


class Device:
    # Constants
    CLA = 0xE0
    INS_GET_PUBLIC_KEY = 0x05
    INS_PARSE_STREAM = 0x08
    INS_SIGN_BLOCK = 0x07
    INS_INIT = 0x06
    INS_SET_TRUSTED_MEMBER = 0x09

    # Enums
    class ParseStreamMode:
        BlockHeader = 0x00
        Command = 0x01
        Signature = 0x02
        Empty = 0x03

    class OutputDataMode:
        none = 0x00
        TrustedParam = 0x01

    class TrustedPropertiesTLV:
        IV = 0x00
        IssuerPublicKey = 0x01
        Xpriv = 0x02
        EphemeralPublicKey = 0x03
        CommandIV = 0x04
        GroupKey = 0x05
        TrustedMember = 0x06

    class TrustedMember:
        def __init__(self, iv, data):
            self.iv = iv
            self.data = data

    class TrustedParams:
        def __init__(self):
            self.members = {}  # Using a dictionary instead of Map
            self.last_trusted_member = None

    # Interfaces
    class SignatureResponse:
        def __init__(self, signature: bytes, sessionKey: bytes):
            self.signature = signature
            self.sessionKey = sessionKey

    class SignBlockHeaderResponse:
        def __init__(self, iv: bytes, issuer: bytes):
            self.iv = iv
            self.issuer = issuer

    class SeedCommandResponse:
        def __init__(self, iv: bytes, xpriv: bytes, commandIv: bytes, ephemeralPublicKey: bytes, groupKey: bytes, trustedMember: bytes or None):
            self.iv = iv
            self.xpriv = xpriv
            self.commandIv = commandIv
            self.ephemeralPublicKey = ephemeralPublicKey
            self.groupKey = groupKey
            self.trustedMember = trustedMember

        def __repr__(self) -> str:
            return f'<IV:{Crypto.to_hex(self.iv),}xpriv:{Crypto.to_hex(self.xpriv)}, commandIV:{Crypto.to_hex(self.commandIv)},ephPublic:{Crypto.to_hex(self.ephemeralPublicKey)}groupKey:{Crypto.to_hex(self.groupKey)},trustedMember:{Crypto.to_hex(self.trustedMember)}>'

    class EmptyCommandResponse:
        pass

    class AddMemberCommandResponse:
        def __init__(self, iv: bytes, trustedMember: bytes):
            self.iv = iv
            self.trustedMember = trustedMember

    class PublishKeyCommandResponse:
        def __init__(self, trustedMember: bytes or None, iv: bytes, xpriv: bytes, commandIv: bytes, ephemeralPublicKey: bytes):
            self.trustedMember = trustedMember
            self.iv = iv
            self.xpriv = xpriv
            self.commandIv = commandIv
            self.ephemeralPublicKey = ephemeralPublicKey

    CommandResponse = Union[SeedCommandResponse, AddMemberCommandResponse,
                            PublishKeyCommandResponse, EmptyCommandResponse]

    def set_trusted_member(transport: BackendInterface, member):
        payload = bytearray([
            Device.TrustedPropertiesTLV.IV, len(member.iv), *member.iv,
            Device.TrustedPropertiesTLV.TrustedMember, len(member.data), *member.data
        ])
        transport.exchange(Device.CLA, Device.INS_SET_TRUSTED_MEMBER,
                           Device.ParseStreamMode.Empty, Device.OutputDataMode.none, payload)

    def parse_block_header(transport: BackendInterface, header):
        # Convert header to bytearray
        header_bytes = bytearray(header)

        # Call the transport.send() function to parse the block header
        response = transport.exchange(Device.CLA, Device.INS_PARSE_STREAM,
                                      Device.ParseStreamMode.BlockHeader, Device.OutputDataMode.none, header_bytes)
        return response.data

    def parseCommand(transport: BackendInterface, command, outputTrustedParam: bool = False):
        command_bytes = bytearray(command)
        response = transport.exchange(Device.CLA, Device.INS_PARSE_STREAM,
                                      Device.ParseStreamMode.Command,  outputTrustedParam, command_bytes)
        return response.data
        # Need to fix outputTrustedParam parameter

    def parse_signature(transport: BackendInterface, signature):
        # Convert header to bytes
        signature_bytes = bytes(signature)

        # Call the transport.send() function to parse the block header

        response = transport.exchange(Device.CLA, Device.INS_PARSE_STREAM,
                                      Device.ParseStreamMode.Signature, Device.OutputDataMode.none, signature_bytes)
        return response.data

    def initFlow(transport: BackendInterface, sessionKey):
        sessionKey_bytes = bytes(sessionKey)
        transport.exchange(Device.CLA, Device.INS_INIT, 0x00, 0x00, sessionKey_bytes)

    def parseEmptyStream(transport: BackendInterface):
        transport.exchange(Device.CLA, Device.INS_PARSE_STREAM,
                           Device.ParseStreamMode.Empty, Device.OutputDataMode.none, bytearray(0))

    def signBlockHeader(transport: BackendInterface, header):
        header_bytes = bytearray(header)
        data = transport.exchange(Device.CLA, Device.INS_SIGN_BLOCK,
                                  Device.ParseStreamMode.BlockHeader, Device.OutputDataMode.none, header_bytes)
        rapduData = data.data
        # print('RAPDU: ' + Crypto.to_hex(rapduDatqa))
        tlvs = TLV.read_all_tlv(rapduData, 0)

        iv = None
        issuer = None

        for tlv in tlvs:
            if tlv['type'] == Device.TrustedPropertiesTLV.IV:
                iv = tlv['value']

            if tlv['type'] == Device.TrustedPropertiesTLV.IssuerPublicKey:
                issuer = tlv['value']

        if iv == None:
            raise ValueError("No IV in response")

        if issuer == None:
            raise ValueError("No issuer in response")

        return (iv, issuer)

    def signCommand(transport: BackendInterface, command):
        response = transport.exchange(Device.CLA, Device.INS_SIGN_BLOCK,
                                      Device.ParseStreamMode.Command, Device.OutputDataMode.none, command)
        return response.data

    def finalizeSignature(transport: BackendInterface):
        response = transport.exchange(Device.CLA, Device.INS_SIGN_BLOCK,
                                      Device.ParseStreamMode.Signature, Device.OutputDataMode.none, bytearray(0))
        # print('RAPDU' + (str(response)))
        sig_len = response.data[0]
        signature = response.data[1:sig_len + 1]
        session_key = response.data[sig_len + 2:]

        # Check Session key is equal to Session Public Key
        # print('\nSession Key: ' + Crypto.to_hex(session_key))
        return (signature, session_key)

    def getPublicKey(transport: BackendInterface):
        response = transport.exchange(Device.CLA, Device.INS_GET_PUBLIC_KEY, 0x00, 0x00, bytes(0))
        return response.data

    def getStatusWord(response):
        return response.status

    def parse_trusted_seed(tlvs) -> SeedCommandResponse:
        iv = None
        xpriv = None
        ephemeral_public_key = None
        command_iv = None
        group_key = None
        trusted_member = None

        for tlv in tlvs:
            if tlv['type'] == Device.TrustedPropertiesTLV.IV:
                iv = tlv['value']
            elif tlv['type'] == Device.TrustedPropertiesTLV.Xpriv:
                xpriv = tlv['value']
            elif tlv['type'] == Device.TrustedPropertiesTLV.EphemeralPublicKey:
                ephemeral_public_key = tlv['value']
            elif tlv['type'] == Device.TrustedPropertiesTLV.CommandIV:
                command_iv = tlv['value']
            elif tlv['type'] == Device.TrustedPropertiesTLV.GroupKey:
                group_key = tlv['value']
            elif tlv['type'] == Device.TrustedPropertiesTLV.TrustedMember:
                trusted_member = tlv['value']
            else:
                raise ValueError("Unknown trusted property")

        if iv is None:
            raise ValueError("No IV in response")
        if xpriv is None:
            raise ValueError("No xpriv in response")
        if ephemeral_public_key is None:
            raise ValueError("No ephemeral public key in response")
        if command_iv is None:
            raise ValueError("No command IV in response")
        if group_key is None:
            raise ValueError("No group key in response")

        return Device.SeedCommandResponse(iv, xpriv, command_iv, ephemeral_public_key, group_key, trusted_member)

    def parse_trusted_add_member(tlvs) -> AddMemberCommandResponse:
        iv = None
        trusted_member = None
        for tlv in tlvs:
            if tlv['type'] == Device.TrustedPropertiesTLV.TrustedMember:
                trusted_member = tlv['value']
            elif tlv['type'] == Device.TrustedPropertiesTLV.IV:
                iv = tlv['value']
        if iv is None:
            raise ValueError("No IV in response")
        if trusted_member is None:
            raise ValueError("No trusted member in response")

        return Device.AddMemberCommandResponse(iv, trusted_member)

    def parse_trusted_publish_key(tlvs) -> PublishKeyCommandResponse:
        iv = ephemeral_public_key = command_iv = trusted_member = xpriv = None

        for tlv in tlvs:
            if tlv['type'] == Device.TrustedPropertiesTLV.IV:
                iv = tlv['value']
            elif tlv['type'] == Device.TrustedPropertiesTLV.EphemeralPublicKey:
                ephemeral_public_key = tlv['value']
            elif tlv['type'] == Device.TrustedPropertiesTLV.CommandIV:
                command_iv = tlv['value']
            elif tlv['type'] == Device.TrustedPropertiesTLV.TrustedMember:
                trusted_member = tlv['value']
            elif tlv['type'] == Device.TrustedPropertiesTLV.Xpriv:
                xpriv = tlv['value']

        if iv is None:
            raise ValueError("No IV in response")
        if ephemeral_public_key is None:
            raise ValueError("No ephemeral public key in response")
        if command_iv is None:
            raise ValueError("No command IV in response")
        if trusted_member is None:
            raise ValueError("No trusted member in response")
        if xpriv is None:
            raise ValueError("No xpriv in response")

        return Device.PublishKeyCommandResponse(trusted_member, iv, xpriv, command_iv, ephemeral_public_key, )

    def parse_trusted_properties(command: Command, raw_properties: bytes):
        tlvs = TLV.read_all_tlv(raw_properties, 0)
        # print(tlvs)
        command_type = command.get_type()

        if command_type in (CommandType.Derive, CommandType.Seed):
            return Device.parse_trusted_seed(tlvs)
        elif command_type == CommandType.AddMember:
            return Device.parse_trusted_add_member(tlvs)
        elif command_type == CommandType.PublishKey:
            return Device.parse_trusted_publish_key(tlvs)
        elif command_type == CommandType.CloseStream:
            return {}
        else:
            raise ValueError("Unsupported command type")


def inject_trusted_properties(command: Command, properties: Device.CommandResponse, secret):
    command_type = command.get_type()

    if command_type == CommandType.Seed:
        seed_command = cast(commands.Seed, command)
        seed_properties = cast(Device.SeedCommandResponse, properties)
        seed_command.encrypted_xpriv = Crypto.decrypt(
            secret, seed_properties.iv, seed_properties.xpriv)
        seed_command.ephemeral_public_key = Crypto.decrypt(
            secret, seed_properties.iv, seed_properties.ephemeralPublicKey)
        seed_command.initialization_vector = Crypto.decrypt(
            secret, seed_properties.iv, seed_properties.commandIv)
        seed_command.group_key = Crypto.decrypt(
            secret, seed_properties.iv, seed_properties.groupKey)
        return seed_command

    elif command_type == CommandType.Derive:
        derive_command = cast(commands.Derive, command)
        derive_properties = cast(Device.SeedCommandResponse, properties)
        derive_command.encrypted_xpriv = Crypto.decrypt(
            secret, derive_properties.iv, derive_properties.xpriv)
        derive_command.ephemeral_public_key = Crypto.decrypt(
            secret, derive_properties.iv, derive_properties.ephemeralPublicKey)
        derive_command.initialization_vector = Crypto.decrypt(
            secret, derive_properties.iv, derive_properties.commandIv)
        derive_command.group_key = Crypto.decrypt(
            secret, derive_properties.iv, derive_properties.groupKey)
        return derive_command
    elif command_type == CommandType.AddMember:
        return command  # No properties to inject
    elif command_type == CommandType.PublishKey:
        publish_key_command = cast(commands.PublishKey, command)
        publish_key_properties = cast(Device.PublishKeyCommandResponse, properties)
        # print('LengthIV' + (Crypto.to_hex(publish_key_properties.iv)))
        publish_key_command.ephemeral_public_key = Crypto.decrypt(
            secret, publish_key_properties.iv, publish_key_properties.ephemeralPublicKey)
        publish_key_command.initialization_vector = Crypto.decrypt(
            secret, publish_key_properties.iv, publish_key_properties.commandIv)
        publish_key_command.encrypted_xpriv = Crypto.decrypt(
            secret, publish_key_properties.iv, publish_key_properties.xpriv)
        return publish_key_command
    elif command_type == CommandType.CloseStream:
        return command  # No properties to inject
    else:
        raise Exception("Unsupported command type")


class PublicKey:
    def __init__(self, public_key: bytearray):
        self.public_key = public_key


class ApduDevice(device):
    def __init__(self, transport: BackendInterface):  # Replace 'Any' with the actual type for the Transport class
        self.transport = transport
        self.session_key_pair = Crypto.randomKeyPair()

    def is_public_key_available(self):
        return False

    def get_public_key(self):
        public_key = Device.getPublicKey(self.transport)
        return PublicKey(public_key)

    def is_connected(self) -> bool:
        response = self.transport.exchange(0xE0, 0x04, 0x00, 0x00)
        sw = response.status
        if sw != 0x9000:
            return False

        app_name = response.data.decode()
        return app_name == "Trustchain"

    def assert_stream_is_valid(self, stream: List[CommandBlock]):
        block_to_sign = sum(1 for block in stream if len(block.signature) == 0)
        # print(stream)
        if block_to_sign != 1:
            raise ValueError(
                f"Stream must contain exactly one block to sign. Found {block_to_sign} blocks to sign.")

    def record_trusted_member(self, trusted_params: Device.TrustedParams, public_key, response_data):
        from CommandStreamDecoder import TLV
    # Parse an APDU result as TLV and find IV and trusted member data.
    # The data is then assigned to a public key. The parsing must set the
    # public key depending on the current step in the flow (e.g add member
    # will issue a trusted member for the added member)
        tlvs = TLV.read_all_tlv(response_data, 0)
        member = None
        iv = None

        if len(public_key) == 0 or (public_key[0] != 0x02 and public_key[0] != 0x03):
            # The public key is not set if it's the device itself
            return

        for tlv in tlvs:
            if tlv['type'] == Device.TrustedPropertiesTLV.TrustedMember:
                member = tlv['value']
            if tlv['type'] == Device.TrustedPropertiesTLV.IV:
                iv = tlv['value']

        if member is None or iv is None:
            return  # Do nothing, trusted member is optional in some cases
            # (e.g. if the trusted member is the device itself)

        trusted_params.members[Crypto.to_hex(member)] = {'iv': iv, 'data': member}
        # Set the last trusted member. This is used to prevent sending the same current trusted member
        # to the device a""gain.
        trusted_params.last_trusted_member = Crypto.to_hex(member)

    def has_trusted_member(self, trusted_params: Device.TrustedParams, public_key):
        return Crypto.to_hex(public_key) in trusted_params.members

    def get_trusted_member(self, trusted_params: Device.TrustedParams, public_key):
        member_hex = Crypto.to_hex(public_key)
        member = trusted_params.members.get(member_hex)
        if member is None:
            raise Exception("Trusted member not found")
        return member

    def set_trusted_member(self, params: Device.TrustedParams, public_key):
        # print("test")
        # Check if the trusted member is already set on the device
        if params.last_trusted_member == Crypto.to_hex(public_key):
            return

        # Verify if the trusted member exists
        if self.has_trusted_member(params, public_key) == False:
            return

        # print("Setting trusted member:" + Crypto.to_hex(public_key))
        return Device.set_trusted_member(self.transport, self.get_trusted_member(params, public_key))

    def parse_block(self, block: CommandBlock, trusted_params: Device.TrustedParams):
        from CommandStreamEncoder import CommandStreamEncoder

        result = None
        # Parse the block header
        self.set_trusted_member(trusted_params, block.issuer)
        result = Device.parse_block_header(
            self.transport, CommandStreamEncoder.encodeBlockHeader(block))
        # Record potential trusted member
        self.record_trusted_member(trusted_params, block.issuer, result)

        for index, command in enumerate(block.commands):
            # Parse the command

            # Set the trusted member depending on the command
            command_type = command.get_type()
            if command_type == CommandType.AddMember:
                self.set_trusted_member(trusted_params, block.issuer)
            elif command_type == CommandType.PublishKey:
                command = cast(commands.PublishKey, command)
                self.set_trusted_member(trusted_params, command.recipient)
            # elif command_type == CommandType.EditMember:
                # self.set_trusted_member(trusted_params, command.member)
            else:
                # Do nothing
                pass

            result = Device.parseCommand(
                self.transport, CommandStreamEncoder.encodeCommand(block, int(index)), True)

            # Record potential trusted member
            if command_type == CommandType.Seed:
                self.record_trusted_member(trusted_params, block.issuer, result)
            elif command_type == CommandType.AddMember:
                command = cast(commands.AddMember, command)
                self.record_trusted_member(trusted_params, command.public_key, result)
            elif command_type == CommandType.PublishKey:
                self.record_trusted_member(trusted_params, command.recipient, result)
            elif command_type == CommandType.Derive:
                self.record_trusted_member(trusted_params, block.issuer, result)
            # elif command_type == CommandType.EditMember:
                # self.record_trusted_member(trusted_params, command.member, result)

        # Parse the block signature
        Device.parse_signature(self.transport, CommandStreamEncoder.encodeSignature(block))

    def parse_stream(self, stream):
        trusted_params = Device.TrustedParams()

        if len(stream) == 0:
            Device.parseEmptyStream(self.transport)

        for block in stream[:-1]:
            self.parse_block(block, trusted_params)

        return trusted_params

    def sign(self, stream: List[CommandBlock], tree):
        from CommandStreamEncoder import CommandStreamEncoder
        session_key = self.session_key_pair
        trusted_properties = []

        # We expect the stream to have a single block to sign (the last one)
        self.assert_stream_is_valid(stream)

        # Init signature flow
        # print('trans' + str(type(self.transport)))
        Device.initFlow(self.transport, session_key['publicKey'])

        # Before signing, we need to parse the stream on device and get trusted params
        trusted_params = self.parse_stream(stream)

        # Create the new block to sign
        block_to_sign = stream[-1]
        # print(block_to_sign)
        trusted_issuer = Device.signBlockHeader(
            self.transport, CommandStreamEncoder.encodeBlockHeader(block_to_sign))

        # Pass all commands to the device
        for command_index in range(len(block_to_sign.commands)):
            # Pass the trusted param allowing the command to the device
            # If we have no trusted param, we need explicit approval
            tp = Device.signCommand(
                self.transport, CommandStreamEncoder.encodeCommand(block_to_sign, command_index))
            trusted_properties.append(Device.parse_trusted_properties(
                block_to_sign.commands[command_index], tp))
            # print(Crypto.to_hex(trusted_properties[0].trustedMember))

        # Finalize block signature
        signature = Device.finalizeSignature(self.transport)

        # Decrypt and inject trusted issuer
        secret = Crypto.ecdh(session_key, signature[1])

        issuer = Crypto.decrypt(secret, trusted_issuer[0], trusted_issuer[1])

        # Inject trusted properties for commands
        for command_index in range(len(block_to_sign.commands)):
            block_to_sign.commands[command_index] = inject_trusted_properties(
                block_to_sign.commands[command_index], trusted_properties[command_index], secret
            )

        block_to_sign.issuer = issuer
        block_to_sign.signature = signature[0]

        return block_to_sign


def createApduDevice(transport: BackendInterface):
    return ApduDevice(transport)
