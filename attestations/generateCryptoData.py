#!/bin/python3
import argparse
import logging
from typing import List
from createKey import check_file, check_exec, setLogger


logger = logging.getLogger(__name__)


def format_data(prefix: str, data: List[str], step: int = 16) -> None:
    """Format key material and print to stdout

    Args:
        prefix (str): Key prefix pour C/H source file declaration
        data (List[str]): Data to be formatted
        step (int): Number of bytes to display per lines
    """

    key_data = ""
    offset = 0
    while offset < len(data):
        key_data += "    " + ", ".join([f"0x{int(x, base=16):02x}" for x in data[offset:offset + step]])
        offset += step
        if offset < len(data):
            key_data += ",\n"

    key = prefix + " {\n" + key_data + "};"
    print(key)


# ===============================================================================
#          Main
# ===============================================================================
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", "-v", action='store_true', help="Verbose mode")
    parser.add_argument('env', type=str, help='CA, key and cert env', choices=["prod", "test"])

    # Check parameters
    args = parser.parse_args()

    env = args.env.upper()

    setLogger(logger, args.verbose)

    dir_path  = f"data/{args.env}"
    key_file  = f"{dir_path}/priv-key.pem"

    check_file(key_file)

    # Extract KEY parameters
    logger.debug(f"Extracting {key_file} parameters...")
    cmd = f"openssl ec -in {key_file} -text -noout"
    stdout = check_exec(cmd)

    # Generate ATTESTATION_KEY
    prefix = f"static const uint8_t {env}_ATTESTATION_KEY[] ="
    key_bytes = "".join(stdout.split("\n")[2:5]).replace(" ", "").split(':')
    if args.env == "prod":
        print(f"PROD_ATTESTATION_KEY='0x{',0x'.join(key_bytes)}'")
    else:
        format_data(prefix, key_bytes)

    # Generate ATTESTATION_PUBKEY
    prefix = f"static const uint8_t {env}_ATTESTATION_PUBKEY[] ="
    key_bytes = "".join(stdout.split("\n")[6:11]).replace(" ", "").split(':')
    format_data(prefix, key_bytes, 13)


if __name__ == "__main__":
    main()
