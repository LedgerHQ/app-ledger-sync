import os
import hashlib
from enum import Enum, auto
from ecdsa import SigningKey  # type: ignore
from ecdsa.util import sigencode_der  # type: ignore


# Private key PEM files have to be named the same (lowercase) as their corresponding enum entries
# Example: for an entry in the Enum named DEV, its PEM file must be at keychain/dev.pem
class Key(Enum):
    CHALLENGE = auto()


_keys: dict[Key, SigningKey] = {}


# Open the corresponding PEM file and load its key in the global dict
def _init_key(key: Key):
    with open(f"{os.path.dirname(__file__)}/{key.name.lower()}.pem", encoding="utf-8") as pem_file:
        _keys[key] = SigningKey.from_pem(pem_file.read(), hashlib.sha256)
    assert (key in _keys) and (_keys[key] is not None)


# Generate a SECP256K1 signature of the given data with the given key
def sign_data(key: Key, data: bytes) -> bytes:
    if key not in _keys:
        _init_key(key)
    return _keys[key].sign_deterministic(data, sigencode=sigencode_der)

# Generate a SECP256K1 signature of the given data with the given key
def get_pub_key(key: Key) -> bytes:
    if key not in _keys:
        _init_key(key)
    return _keys[key].get_verifying_key().to_string('compressed')
