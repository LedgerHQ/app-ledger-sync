import hashlib

from hdwallet import HDWallet
from ecdsa import SigningKey, SECP256k1

SPECULOS_MNEMONIC = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

SEED_ID_PATH = "m/99'/99'"


def generate_private_key_from_mnemonic(mnemonic_phrase, derivation_path):
    hdwallet = HDWallet()

    hdwallet.from_mnemonic(mnemonic=SPECULOS_MNEMONIC)
    hdwallet.from_path(path=SEED_ID_PATH)

    return hdwallet.private_key()


def sign_hash(private_key, hash_to_sign):
    # Convert the private key to an ecdsa SigningKey object
    signing_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)

    # Sign the hash
    signature = signing_key.sign_rfc6979(hash_to_sign)

    return signature.hex()


def compute_challenge_hash(challenge):
    hash_object = hashlib.sha256(challenge)
    print(f"Challenge hash: {hash_object.digest().hex()}")
    return hash_object.digest()


def sign_challenge_hash(challenge_hash):
    # Derive Private Key
    private_key = generate_private_key_from_mnemonic(SPECULOS_MNEMONIC, SEED_ID_PATH)
    print(f"Private Key: {private_key}")

    # Use it to sign hash
    signature = sign_hash(private_key, challenge_hash)

    print(f"Signature: {signature}")

    return signature
