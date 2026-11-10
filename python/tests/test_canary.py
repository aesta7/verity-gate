"""Offline test for the canary runner — a fake gate implements the rules.

Run:  python3 tests/test_canary.py   (plain script, asserts only)
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from verity_gate import GateClient
from verity_gate.canary import run_canary
from verity_gate.cli import main as cli_main


class FakeGate:
    """Implements the published rule surface: R1 veto, R2 money,
    R4 denylist + delete language, R3 velocity (>30 reads -> ESCALATE)."""

    def __init__(self):
        self.seq = 100
        self.reads = {}

    def __call__(self, method, url, headers, body_bytes):
        assert url.endswith("/verdict")
        body = json.loads(body_bytes.decode())
        action = body["action"].lower()
        cls = body.get("consequence_class", "")
        self.seq += 1
        if "purge" in action or cls == "destructive":
            return 200, {"verdict": "VETO", "rule_hits": ["R1"], "seq": self.seq}
        if cls == "money" or (body.get("amount_usd") or 0) > 0:
            return 200, {"verdict": "ESCALATE", "rule_hits": ["R2"], "seq": self.seq}
        if body.get("target") == "/etc/passwd":
            return 200, {"verdict": "ESCALATE", "rule_hits": ["R4_denylist"], "seq": self.seq}
        if action.startswith("delete"):
            return 200, {"verdict": "ESCALATE", "rule_hits": ["R4_delete_language"], "seq": self.seq}
        if cls == "read":
            n = self.reads.get(body["actor"], 0) + 1
            self.reads[body["actor"]] = n
            if n > 30:
                return 200, {"verdict": "ESCALATE", "rule_hits": ["R3"], "seq": self.seq}
        return 200, {"verdict": "ALLOW", "rule_hits": [], "seq": self.seq}


def test_canary_passes_against_fake_gate():
    gate = FakeGate()
    client = GateClient("vk_test", transport=gate)
    ok, lines = run_canary(client)
    assert ok, "\n".join(lines)
    assert len(lines) == 6
    assert "VETO" in lines[1]
    assert "ESCALATE" in lines[5]


def test_cli_without_key_exits_2():
    old = os.environ.pop("VERITY_GATE_KEY", None)
    # GateClient() inside the CLI reads the environment; but the CLI builds
    # its own client with the real transport — without a key it must refuse
    # before any network use.
    try:
        assert cli_main(["canary"]) == 2
    finally:
        if old is not None:
            os.environ["VERITY_GATE_KEY"] = old


if __name__ == "__main__":
    test_canary_passes_against_fake_gate()
    print("canary fake-gate test: PASS")
    test_cli_without_key_exits_2()
    print("cli no-key test: PASS")
