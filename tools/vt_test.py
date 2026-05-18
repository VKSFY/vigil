"""
Ad-hoc test driver for the VirusTotal integration. Run after exporting
VIGIL_VT_API_KEY. Exercises lookup_hash() with two SHA256s and prints the
same CLI block scan.py would emit on a MALICIOUS verdict.

    $env:VIGIL_VT_API_KEY = "your_key_here"
    python tools/vt_test.py

Not part of the shipping pipeline — purely a smoke test.
"""
from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from virustotal import lookup_hash, render_cli_block, ENV_VAR  # noqa: E402


# Known malicious sample on MalwareBazaar and VirusTotal — WannaCry's
# main worm binary, indexed since 2017. Swap in any SHA256 from
# https://bazaar.abuse.ch/browse/ if you want a fresher sample.
WANNACRY = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"

# A hash that should not be in VT's corpus — derived deterministically
# from a throwaway string, so it corresponds to no real file.
NOT_IN_DB = hashlib.sha256(b"vigil-test-not-in-vt-database-2026").hexdigest()


def main() -> int:
    key = os.environ.get(ENV_VAR)
    if not key:
        print(f"error: {ENV_VAR} not set", file=sys.stderr)
        return 2

    cases = [
        ("known malicious (WannaCry, MalwareBazaar/VT)", WANNACRY),
        ("random throwaway hash (expect 404)",           NOT_IN_DB),
    ]
    for label, sha in cases:
        print()
        print("#" * 70)
        print(f"# {label}")
        print(f"# sha256: {sha}")
        print("#" * 70)
        result = lookup_hash(sha, key)
        if result is None:
            print("(lookup_hash returned None — see warning above)")
            continue
        print(render_cli_block(result))
        print(f"  raw dict: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
