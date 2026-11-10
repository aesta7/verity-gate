"""verity_gate — a client and integration helpers for the Verity Gate API.

Put the gate in your agent's path: submit each proposed action before it
executes, and act on the verdict — ALLOW, VETO, or ESCALATE — that comes
back sealed into the audit chain.

    from verity_gate import GateClient, guarded

    client = GateClient("vk_...")  # key claimed at verityverdict.com/start/

    @guarded(client, actor="my-agent", action="read a customer record",
             consequence_class="read")
    def read_record(record_id):
        ...

    result, verdict = read_record(42)  # shadow mode: always runs, verdict attached
"""
from .client import (
    BASE_URL,
    AttestationRequired,
    GateClient,
    NotInGoodStanding,
    Unauthorized,
    Verdict,
    VerityError,
)
from .guard import GateEscalation, GateVeto, call, check, guarded

__version__ = "0.2.1"

__all__ = [
    "BASE_URL",
    "AttestationRequired",
    "GateClient",
    "GateEscalation",
    "GateVeto",
    "NotInGoodStanding",
    "Unauthorized",
    "Verdict",
    "VerityError",
    "call",
    "check",
    "guarded",
]
