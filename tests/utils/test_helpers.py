"""
Shared utility functions for test files to avoid code duplication.
"""

from constants import DEFAULT_TOPIC

from utils.CommandStream import CommandStream
from utils.NobleCrypto import Crypto, DerivationPath
from utils.streamTree import StreamTree

ROOT_DERIVATION_PATH = "16'/0'"


def get_derivation_path(index: int) -> list[int]:
    """
    Generate derivation path for given index.

    Args:
        index: The index for the derivation path

    Returns:
        List[int]: The derivation path as an index array
    """
    return DerivationPath.to_index_array(f"{ROOT_DERIVATION_PATH}/{index}'")


def create_seed_and_derive_stream(device_instance, derivation_index: int = 0, topic: bytes | None = None):
    """
    Utility function to create a root seed stream and derive a new stream from it.
    This prevents adding blocks directly to the root stream and follows the proper flow.

    Args:
        device_instance: The device instance to use for issuing commands
        derivation_index: The index for the derivation path (default: 0)
        topic: The topic bytes to use for seeding (default: DEFAULT_TOPIC)

    Returns:
        tuple: (derived_stream, stream_tree)
    """
    if topic is None:
        topic = Crypto.from_hex(DEFAULT_TOPIC)

    # Create the root seed stream
    root_stream = CommandStream()
    root_stream = root_stream.edit().seed(topic).issue(device_instance)
    tree = StreamTree.from_streams(root_stream)

    # Derive a new stream from the root
    derived_stream = CommandStream()
    derived_stream = derived_stream.edit().derive(get_derivation_path(derivation_index)).issue(device_instance, tree)
    tree = tree.update(derived_stream)

    return derived_stream, tree
