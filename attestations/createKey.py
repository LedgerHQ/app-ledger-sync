#!/bin/python3
import argparse
import logging
import os
import subprocess
import sys

import coloredlogs

logger = logging.getLogger(__name__)


def setLogger(log: logging.Logger, verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    coloredlogs.install(level=level, fmt="%(message)s", logger=log)


def check_exec(cmdline: str) -> str:
    result = subprocess.run(cmdline, shell=True, check=True, capture_output=True)
    if result.returncode != 0:
        logger.error(f"[ERROR] Failed to execute {cmdline}")
        logger.error(f"[ERROR] stderr: {result.stderr.decode()}")
        sys.exit(result.returncode)
    return result.stdout.decode()


def check_file(filename: str, exist: bool = True) -> str:
    logger.debug(f"Checking {filename}...")
    if os.path.isfile(filename) != exist:
        msg = "already" if not exist else "does not"
        logger.error(f"[ERROR] {filename} {msg} exist")
        sys.exit(1)


# ===============================================================================
#          Main
# ===============================================================================
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    # Check parameters
    args = parser.parse_args()

    setLogger(logger, args.verbose)

    dir_path = "data/test"
    key_name = "priv-key.pem"
    key_file = f"{dir_path}/{key_name}"

    # Create dir if not present
    os.makedirs(dir_path, mode=0o700, exist_ok=True)

    # Generated to stdout: giving openssl -out would have it open, and follow, a path that
    # another process can replace with a symlink after any existence check
    logger.debug(f"Creating {key_file}...")
    result = subprocess.run(
        ["openssl", "ecparam", "-name", "secp256k1", "-genkey"],
        check=True,
        capture_output=True,
    )

    # O_EXCL is the no-overwrite rule itself rather than a check preceding it, and O_NOFOLLOW
    # refuses a symlinked destination, as does opening the parent directory first
    dir_fd = os.open(dir_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        key_fd = os.open(key_name, flags, 0o600, dir_fd=dir_fd)
    except FileExistsError:
        logger.error(f"[ERROR] {key_file} already exist")
        sys.exit(1)
    finally:
        os.close(dir_fd)

    with os.fdopen(key_fd, "wb") as key:
        key.write(result.stdout)
    logger.info(f"Created {key_file}")


if __name__ == "__main__":
    main()
