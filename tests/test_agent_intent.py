import pytest
from constants import DEFAULT_TOPIC
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID
from utils.ApduDevice import Automation
from utils.CommandBlock import Permissions
from utils.CommandStream import CommandStream
from utils.index import device
from utils.NobleCrypto import Crypto
from utils.streamTree import StreamTree
from utils.test_helpers import get_agent_intent_path

# Fixed private key for snapshot-stable tests: the fingerprint of the agent's public key is
# shown on the Add Agent screen, so it must be deterministic across test runs.
AGENT_FIXED_PRIVATE_KEY = bytes([0x01] * 32)


def create_agent_intent_stream(device_instance, derivation_index: int = 0, topic=None):
    """Create a seed + Agent Intent derive stream (AppID 18)."""
    if topic is None:
        topic = Crypto.from_hex(DEFAULT_TOPIC)
    root_stream = CommandStream()
    root_stream = root_stream.edit().seed(topic).issue(device_instance)
    tree = StreamTree.from_streams(root_stream)
    derived = CommandStream()
    derived = derived.edit().derive(get_agent_intent_path(derivation_index)).issue(device_instance, tree)
    tree = tree.update(derived)
    return derived, tree


# fmt: off
# --- AGENT_FULL (CAN_ENCRYPT | CAN_DERIVE): "Enable website access for your agent?" (1 screen) ---
enable_agent_access_happy_stax = [
    NavInsID.USE_CASE_CHOICE_CONFIRM,
    NavInsID.USE_CASE_STATUS_DISMISS,
]
enable_agent_access_reject_stax = [
    NavInsID.USE_CASE_CHOICE_REJECT,
    NavInsID.USE_CASE_STATUS_DISMISS,
]

# Nano: short-text choice screen
#   RIGHT x1 to confirm, RIGHT x2 to reject
R, B = NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK
enable_agent_access_happy_nano = [
    R, B,    # confirm
    B,       # status dismiss
]
enable_agent_access_reject_nano = [
    R, R, B, # reject
]

# --- AGENT_REGISTER (CAN_ENCRYPT): "Add agent" (1 screen, fingerprint + hint shown) ---
register_agent_happy_stax = [
    NavInsID.USE_CASE_CHOICE_CONFIRM,
    NavInsID.USE_CASE_STATUS_DISMISS,
]
register_agent_reject_stax = [
    NavInsID.USE_CASE_CHOICE_REJECT,
    NavInsID.USE_CASE_STATUS_DISMISS,
]

# Nano: fingerprint + hint spread over 2 pages → RIGHT x3 to confirm, RIGHT x4 to reject
register_agent_happy_nano = [
    R, R, R, B,    # confirm
    B,             # status dismiss
]
register_agent_reject_nano = [
    R, R, R, R, B, # reject
]
# fmt: on


def test_enable_agent_access_happy_path(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    if backend.device.is_nano:
        instructions = enable_agent_access_happy_nano
    else:
        instructions = enable_agent_access_happy_stax

    alice = device.apdu(backend)
    agent = device.software_from_key(AGENT_FIXED_PRIVATE_KEY)
    agent_pubkey = agent.get_public_key()

    stream, tree = create_agent_intent_stream(alice)

    automation = Automation(navigator, test_name=test_name, instructions=instructions)
    alice.update_automation(automation)
    stream = stream.edit().add_member("Bob's agent", agent_pubkey, Permissions.AGENT_FULL, publish_key=False).issue(alice, tree)

    blocks = stream.get_blocks()
    assert len(blocks) > 0
    assert len(blocks[-1].signature) > 0


def test_enable_agent_access_decline(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    if backend.device.is_nano:
        instructions = enable_agent_access_reject_nano
    else:
        instructions = enable_agent_access_reject_stax

    alice = device.apdu(backend)
    agent = device.software_from_key(AGENT_FIXED_PRIVATE_KEY)
    agent_pubkey = agent.get_public_key()

    stream, tree = create_agent_intent_stream(alice)

    automation = Automation(navigator, test_name=test_name, instructions=instructions)
    alice.update_automation(automation)
    with pytest.raises(ExceptionRAPDU):
        stream.edit().add_member("Bob's agent", agent_pubkey, Permissions.AGENT_FULL, publish_key=False).issue(alice, tree)


def test_register_agent_happy_path(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    if backend.device.is_nano:
        instructions = register_agent_happy_nano
    else:
        instructions = register_agent_happy_stax

    alice = device.apdu(backend)
    agent = device.software_from_key(AGENT_FIXED_PRIVATE_KEY)
    agent_pubkey = agent.get_public_key()

    stream, tree = create_agent_intent_stream(alice)

    automation = Automation(navigator, test_name=test_name, instructions=instructions)
    alice.update_automation(automation)
    stream = (
        stream.edit().add_member("Bob's agent", agent_pubkey, Permissions.AGENT_REGISTER, publish_key=False).issue(alice, tree)
    )

    blocks = stream.get_blocks()
    assert len(blocks) > 0
    assert len(blocks[-1].signature) > 0


def test_register_agent_decline(backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    if backend.device.is_nano:
        instructions = register_agent_reject_nano
    else:
        instructions = register_agent_reject_stax

    alice = device.apdu(backend)
    agent = device.software_from_key(AGENT_FIXED_PRIVATE_KEY)
    agent_pubkey = agent.get_public_key()

    stream, tree = create_agent_intent_stream(alice)

    automation = Automation(navigator, test_name=test_name, instructions=instructions)
    alice.update_automation(automation)
    with pytest.raises(ExceptionRAPDU):
        stream.edit().add_member("Bob's agent", agent_pubkey, Permissions.AGENT_REGISTER, publish_key=False).issue(alice, tree)


def test_add_member_invalid_permissions(backend: BackendInterface) -> None:
    """AppID 18 with permissions not in {CAN_ENCRYPT|CAN_DERIVE, CAN_ENCRYPT} → immediate SW_WRONG_DATA."""
    alice = device.apdu(backend)
    agent = device.software_from_key(AGENT_FIXED_PRIVATE_KEY)
    agent_pubkey = agent.get_public_key()

    stream, tree = create_agent_intent_stream(alice)

    # 0x07 = CAN_ENCRYPT|CAN_DERIVE|CAN_ADD_BLOCK — not a valid AppID 18 case → SW_WRONG_DATA, no UI shown
    with pytest.raises(ExceptionRAPDU):
        stream.edit().add_member("bad", agent_pubkey, 0x07, publish_key=False).issue(alice, tree)
