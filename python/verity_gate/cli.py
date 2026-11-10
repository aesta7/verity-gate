"""Command line for verity-gate.

    verity-gate canary

Runs the six canary checks against the live gate with the caller's own
key (from $VERITY_GATE_KEY). Exit status 0 when every canary returns
its expected verdict.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .canary import run_canary
from .client import GateClient, VerityError

NO_KEY = (
    "verity-gate: no caller key found. The operator claims a free shadow key\n"
    "at https://verityverdict.com/start/ and exports it:\n"
    "    export VERITY_GATE_KEY=vk_...\n"
    "Agents never provision their own keys."
)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verity-gate", description="Verity gate command line."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("canary", help="run the six canary checks against the live gate")
    args = parser.parse_args(argv)

    if args.command == "canary":
        client = GateClient()
        if not client.api_key:
            print(NO_KEY, file=sys.stderr)
            return 2
        try:
            ok, lines = run_canary(client)
        except VerityError as e:
            print(f"verity-gate: the gate answered with an error: {e}", file=sys.stderr)
            return 1
        for line in lines:
            print(line)
        print("canary: all checks passed" if ok else "canary: SOME CHECKS FAILED")
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
