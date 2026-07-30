#!/usr/bin/env python3
"""
Quick verification script to test the refactored utility functions.
This doesn't actually run the tests but verifies the function signatures and imports.
"""

import os
import sys

# Add the tests directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Test imports
    from utils.test_helpers import create_seed_and_derive_stream, get_derivation_path

    print("✓ Successfully imported utility functions")

    # Test function signatures
    import inspect

    # Check get_derivation_path
    sig_gd = inspect.signature(get_derivation_path)
    print(f"✓ get_derivation_path signature: {sig_gd}")

    # Check create_seed_and_derive_stream
    sig_cs = inspect.signature(create_seed_and_derive_stream)
    print(f"✓ create_seed_and_derive_stream signature: {sig_cs}")

    # Test the constants
    from utils.test_helpers import ROOT_DERIVATION_PATH

    print(f"✓ ROOT_DERIVATION_PATH = {ROOT_DERIVATION_PATH}")

    print("\n✓ All basic checks passed - the refactoring appears to be correct")

except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Unexpected error: {e}")
    sys.exit(1)
