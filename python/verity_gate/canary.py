"""The six canary checks, shared by the CLI and the tests.

An adopter runs these against the live gate with their own caller key
and watches the rules fire: one clean read allowed, one destructive
action vetoed, three escalations, and a velocity burst that trips the
rate rule part-way through. Expected verdicts and proposal shapes are the canonical
self-test published in the gate's /api/ documentation: the denylist
rule reads the target field, so /etc/passwd travels as `target`.
"""
from __future__ import annotations

from typing import List, Tuple

from .client import GateClient

ACTOR = "canary"

SINGLES: List[Tuple[str, dict, str]] = [
    (
        "read the canary order",
        {"actor": ACTOR, "action": "fetch order status",
         "consequence_class": "read", "target": "canary-test order #0001"},
        "ALLOW",
    ),
    (
        "purge all backups",
        {"actor": ACTOR, "action": "purge all backups", "consequence_class": "destructive",
         "target": "canary-test backup volume"},
        "VETO",
    ),
    (
        "send a $5,000 payout",
        {"actor": ACTOR, "action": "send payout", "consequence_class": "money",
         "amount_usd": 5000, "target": "canary-test vendor acct"},
        "ESCALATE",
    ),
    (
        "read /etc/passwd",
        {"actor": ACTOR, "action": "read config file",
         "consequence_class": "access", "target": "/etc/passwd"},
        "ESCALATE",
    ),
    (
        "delete user records",
        {"actor": ACTOR, "action": "delete user records", "consequence_class": "write",
         "target": "canary-test customer table"},
        "ESCALATE",
    ),
]

BURST_COUNT = 35
BURST_PROPOSAL = {"actor": ACTOR, "action": "read inventory levels",
                  "consequence_class": "read"}


def run_canary(client: GateClient) -> Tuple[bool, List[str]]:
    """Fire all six canaries. Returns (all_passed, report_lines)."""
    lines: List[str] = []
    ok = True
    for i, (label, proposal, expected) in enumerate(SINGLES, start=1):
        v = client.verdict(**proposal)
        passed = v.verdict == expected
        ok = ok and passed
        mark = "PASS" if passed else "FAIL"
        lines.append(
            f"canary {i}/6  {label:<24} -> {v.verdict:<8} "
            f"(expected {expected}; rule {v.rule}; seq {v.seq})  {mark}"
        )
    verdicts = [client.verdict(**BURST_PROPOSAL).verdict for _ in range(BURST_COUNT)]
    escalations = verdicts.count("ESCALATE")
    passed = escalations >= 1
    ok = ok and passed
    mark = "PASS" if passed else "FAIL"
    lines.append(
        f"canary 6/6  {BURST_COUNT} reads in a burst        -> "
        f"{verdicts.count('ALLOW')} ALLOW, {escalations} ESCALATE "
        f"(expected ESCALATE on late rows)  {mark}"
    )
    return ok, lines
