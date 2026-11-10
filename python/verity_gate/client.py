"""Client for the Verity Gate API (https://api.verityverdict.com/api/v1).

Standard library only — no third-party dependencies.

Every call carries the caller key as a bearer credential. Keys are issued
to a human operator, never to the agent itself: claim a free shadow key at
https://verityverdict.com/start/ (shown exactly once), or take an
enforcement key at checkout.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

BASE_URL = "https://api.verityverdict.com/api/v1"

# A transport takes (method, url, headers, body_bytes) and returns
# (http_status, decoded_json_body). Inject one to test without a network.
Transport = Callable[
    [str, str, Dict[str, str], Optional[bytes]], Tuple[int, Any]
]


class VerityError(Exception):
    """Any failure talking to the gate.

    Carries the HTTP ``status`` and the decoded response ``body`` when the
    gate answered; both are ``None`` when the gate could not be reached.
    """

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class Unauthorized(VerityError):
    """HTTP 401 — the caller key was missing or not recognized."""


class NotInGoodStanding(VerityError):
    """HTTP 402 — the caller's subscription is not in good standing."""


class AttestationRequired(VerityError):
    """The gate refused the call: this caller must attest before verdicts."""


@dataclass
class Verdict:
    """One verdict from the gate, as returned by POST /verdict."""

    verdict: str
    rule: Optional[str] = None
    seq: Optional[int] = None
    chain_hash: Optional[str] = None
    signature: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    @property
    def vetoed(self) -> bool:
        return self.verdict == "VETO"

    @property
    def escalated(self) -> bool:
        return self.verdict == "ESCALATE"

    @classmethod
    def from_body(cls, body: Optional[Dict[str, Any]]) -> "Verdict":
        """Parse a verdict response defensively.

        The rule may arrive as ``rule``, ``rule_id``, or the first entry of
        ``rule_hits``; the chain sequence as ``seq`` or ``chain_seq``. The
        full body is kept on ``raw`` either way.
        """
        body = body or {}
        rule_hits = body.get("rule_hits") or []
        rule = body.get("rule") or body.get("rule_id")
        if not rule and rule_hits:
            rule = rule_hits[0]
        seq = body.get("seq")
        if seq is None:
            seq = body.get("chain_seq")
        return cls(
            verdict=str(body.get("verdict") or "").upper(),
            rule=rule,
            seq=seq,
            chain_hash=body.get("chain_hash"),
            signature=body.get("signature"),
            raw=body,
        )


def _urllib_transport(timeout: float) -> Transport:
    def transport(
        method: str,
        url: str,
        headers: Dict[str, str],
        body_bytes: Optional[bytes],
    ) -> Tuple[int, Any]:
        req = urllib.request.Request(
            url, data=body_bytes, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"error": raw}
            return e.code, parsed

    return transport


class GateClient:
    """A caller-key client for the Verity gate.

    >>> client = GateClient("vk_...")  # a key you claimed at /start/
    >>> v = client.verdict(actor="my-agent", action="read a customer record",
    ...                    consequence_class="read")
    >>> v.verdict
    'ALLOW'
    """

    def __init__(
        self,
        api_key=None,
        base_url=None,
        timeout: float = 10,
        transport: Optional[Transport] = None,
    ) -> None:
        # Zero-config: with no arguments, the key and base URL come from
        # the operator's environment (VERITY_GATE_KEY / VERITY_GATE_BASE_URL).
        self.api_key = api_key or os.environ.get("VERITY_GATE_KEY")
        self.base_url = (base_url or os.environ.get("VERITY_GATE_BASE_URL") or BASE_URL).rstrip("/")
        self.timeout = timeout
        self._transport: Transport = transport or _urllib_transport(timeout)

    # -- plumbing ---------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        auth: bool = True,
    ) -> Any:
        url = self.base_url + path
        headers: Dict[str, str] = {
            "Accept": "application/json",
            # The API's edge refuses the urllib default agent string (403);
            # identify the client instead.
            "User-Agent": "verity-gate-python/0.2.1",
        }
        if auth and self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body_bytes: Optional[bytes] = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body_bytes = json.dumps(payload).encode("utf-8")
        try:
            status, data = self._transport(method, url, headers, body_bytes)
        except VerityError:
            raise
        except Exception as exc:  # network failure, DNS, timeout, ...
            raise VerityError(
                f"gate unreachable: {exc}", status=None, body=None
            ) from exc
        if status == 401:
            raise Unauthorized("unauthorized", status=status, body=data)
        if status == 402:
            raise NotInGoodStanding(
                "caller_not_in_good_standing", status=status, body=data
            )
        if status is not None and status >= 400:
            if isinstance(data, dict) and data.get("error") == "attestation_required":
                raise AttestationRequired(
                    "attestation_required", status=status, body=data
                )
            detail = data.get("error") if isinstance(data, dict) else None
            raise VerityError(
                f"gate returned HTTP {status}" + (f": {detail}" if detail else ""),
                status=status,
                body=data,
            )
        return data

    # -- the API ----------------------------------------------------------

    def verdict(
        self,
        actor: str,
        action: str,
        consequence_class: str,
        target: Optional[str] = None,
        amount_usd: Optional[float] = None,
    ) -> Verdict:
        """Submit one proposed action; get back ALLOW, VETO, or ESCALATE."""
        payload: Dict[str, Any] = {
            "actor": actor,
            "action": action,
            "consequence_class": consequence_class,
        }
        if target is not None:
            payload["target"] = target
        if amount_usd is not None:
            payload["amount_usd"] = amount_usd
        return Verdict.from_body(self._request("POST", "/verdict", payload))

    def attest(self, purpose: str, domains: List[str]) -> Any:
        """Seal a signed attestation of standing intent into the chain.

        Some callers are refused verdicts until they have attested: the
        attestation states the caller's purpose and the domains it will
        act in, before the first proposal is judged against it.
        """
        return self._request(
            "POST", "/attest", {"purpose": purpose, "domains": list(domains)}
        )

    def revoke_attestation(self) -> Any:
        """Revoke this caller's attestation; the revocation is itself sealed."""
        return self._request("POST", "/attest/revoke", {})

    def chain(self, limit: Optional[int] = None) -> Any:
        """Read the audit chain back — metadata only, no proposal contents."""
        path = "/chain"
        if limit is not None:
            path += f"?limit={int(limit)}"
        return self._request("GET", path)

    def verify_chain(self) -> Any:
        """Replay the chain from the first record and confirm every link."""
        return self._request("GET", "/chain/verify")

    def pubkey(self) -> Any:
        """The gate's Ed25519 signing key. Public — no credential needed."""
        return self._request("GET", "/chain/pubkey", auth=False)

    def health(self) -> Any:
        """Service status, and whether the chain database is bound."""
        return self._request("GET", "/health", auth=False)
