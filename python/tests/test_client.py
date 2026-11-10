"""Offline tests for verity_gate — no network, no real key.

Every test drives the client through an injected fake transport.

Run either way:
    python3 -m pytest tests/test_client.py
    python3 tests/test_client.py          # plain script, asserts only
"""
import contextlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

try:
    import pytest  # noqa: F401  (present when run under pytest)
except ImportError:
    pytest = None

from verity_gate import GateClient, NotInGoodStanding, Unauthorized, VerityError
from verity_gate.guard import GateEscalation, GateVeto, call, guarded


@contextlib.contextmanager
def assert_raises(exc_type):
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


class FakeTransport:
    """transport(method, url, headers, body_bytes) -> (status, json)."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def __call__(self, method, url, headers, body_bytes):
        self.calls.append((method, url, headers, body_bytes))
        return self.handler(method, url, headers, body_bytes)


def client_returning(status, body):
    return GateClient("vk_test", transport=FakeTransport(lambda *a: (status, body)))


ALLOW_BODY = {
    "verdict": "ALLOW",
    "rule_hits": [],
    "seq": 19,
    "chain_hash": "abc123",
    "signature": "sig",
}
VETO_BODY = {"verdict": "VETO", "rule_hits": ["R1"], "seq": 20, "chain_hash": "def456"}
ESCALATE_BODY = {"verdict": "ESCALATE", "rule": "R2", "seq": 21}


# -- verdict parsing --------------------------------------------------------


def test_verdict_parsing_allow():
    v = client_returning(200, ALLOW_BODY).verdict(
        actor="a", action="read a record", consequence_class="read"
    )
    assert v.verdict == "ALLOW"
    assert v.allowed and not v.vetoed and not v.escalated
    assert v.rule is None  # empty rule_hits -> no rule
    assert v.seq == 19
    assert v.chain_hash == "abc123"
    assert v.signature == "sig"
    assert v.raw == ALLOW_BODY


def test_verdict_parsing_rule_hits_list_form():
    v = client_returning(200, VETO_BODY).verdict(
        actor="a", action="purge all backups", consequence_class="destructive"
    )
    assert v.verdict == "VETO" and v.vetoed
    assert v.rule == "R1"  # first entry of rule_hits
    assert v.seq == 20


def test_verdict_parsing_fallback_fields():
    body = {"verdict": "escalate", "rule_id": "R9", "chain_seq": 7}
    v = client_returning(200, body).verdict(
        actor="a", action="x", consequence_class="money", amount_usd=5000
    )
    assert v.verdict == "ESCALATE" and v.escalated
    assert v.rule == "R9"  # rule_id fallback
    assert v.seq == 7  # chain_seq fallback


def test_request_shape_and_auth_header():
    t = FakeTransport(lambda *a: (200, ALLOW_BODY))
    c = GateClient("vk_test", transport=t)
    c.verdict(
        actor="agent-1",
        action="send payout",
        consequence_class="money",
        target="vendor acct",
        amount_usd=5000,
    )
    method, url, headers, body_bytes = t.calls[0]
    assert method == "POST"
    assert url == "https://api.verityverdict.com/api/v1/verdict"
    assert headers["Authorization"] == "Bearer vk_test"
    assert json.loads(body_bytes) == {
        "actor": "agent-1",
        "action": "send payout",
        "consequence_class": "money",
        "target": "vendor acct",
        "amount_usd": 5000,
    }


# -- errors -------------------------------------------------------------------


def test_401_raises_unauthorized():
    c = client_returning(401, {"error": "unauthorized"})
    with assert_raises(Unauthorized):
        c.verdict(actor="a", action="x", consequence_class="read")


def test_402_raises_not_in_good_standing():
    c = client_returning(402, {"error": "caller_not_in_good_standing"})
    with assert_raises(NotInGoodStanding):
        c.verdict(actor="a", action="x", consequence_class="read")


# -- guard semantics ------------------------------------------------------------


def test_enforce_veto_blocks_execution():
    ran = []
    fn = guarded(
        client_returning(200, VETO_BODY),
        actor="a",
        action="purge all backups",
        consequence_class="destructive",
        mode="enforce",
    )(lambda: ran.append(True))
    with assert_raises(GateVeto) as _:
        fn()
    assert ran == []  # the function never ran


def test_enforce_escalate_without_callback_blocks():
    ran = []
    fn = guarded(
        client_returning(200, ESCALATE_BODY),
        actor="a",
        action="send payout",
        consequence_class="money",
        mode="enforce",
    )(lambda: ran.append(True))
    with assert_raises(GateEscalation):
        fn()
    assert ran == []


def test_enforce_escalate_with_approving_callback_runs():
    fn = guarded(
        client_returning(200, ESCALATE_BODY),
        actor="a",
        action="send payout",
        consequence_class="money",
        mode="enforce",
        on_escalate=lambda v: True,
    )(lambda: "paid")
    assert fn() == "paid"  # enforce mode returns the bare result


def test_enforce_allow_runs():
    fn = guarded(
        client_returning(200, ALLOW_BODY),
        actor="a",
        action="read a record",
        consequence_class="read",
        mode="enforce",
    )(lambda: "record")
    assert fn() == "record"


def test_shadow_executes_despite_veto():
    fn = guarded(
        client_returning(200, VETO_BODY),
        actor="a",
        action="purge all backups",
        consequence_class="destructive",
        mode="shadow",
    )(lambda: "done")
    result, verdict = fn()
    assert result == "done"  # shadow always runs
    assert verdict is not None and verdict.vetoed


def test_enforce_fails_closed_on_transport_exception():
    def boom(*a):
        raise ConnectionError("no route to host")

    c = GateClient("vk_test", transport=FakeTransport(boom))
    ran = []
    fn = guarded(
        c, actor="a", action="x", consequence_class="read", mode="enforce"
    )(lambda: ran.append(True))
    with assert_raises(VerityError):
        fn()
    assert ran == []  # gate unreachable in enforce mode -> nothing ran


def test_shadow_fails_open_on_transport_exception():
    def boom(*a):
        raise ConnectionError("no route to host")

    c = GateClient("vk_test", transport=FakeTransport(boom))
    result, verdict = call(
        c,
        lambda: "ran anyway",
        actor="a",
        action="x",
        consequence_class="read",
        mode="shadow",
    )
    assert result == "ran anyway"
    assert verdict is None  # the gap is visible, not hidden


if __name__ == "__main__":
    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - report and continue
            failures += 1
            print(f"FAIL {name}: {type(e).__name__}: {e}")
        else:
            print(f"PASS {name}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
