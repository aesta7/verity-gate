"""Put the gate in the path of a function call.

``guarded`` decorates a function so that a proposal describing the call is
submitted to the gate *before* the function runs. What happens next
depends on the mode:

- ``shadow`` (the default): the function always runs. The call returns
  ``(result, verdict)`` so you can read what the gate would have decided.
  Run this way first, while you watch.
- ``enforce``: the function runs only on ALLOW, and the call returns the
  function's result. VETO raises :class:`GateVeto` and the function never
  runs. ESCALATE consults the ``on_escalate`` callback when one is given —
  the function runs only if it returns True — and otherwise raises
  :class:`GateEscalation`.

Failure semantics are part of the contract, not an accident:

- In ``enforce`` mode, the gate failing is the action failing. If the
  gate cannot be reached, or refuses the call, the function does **not**
  run and the error propagates. Fail closed.
- In ``shadow`` mode, the watch must not break the work it watches. If
  the gate cannot be reached, the function runs anyway, a warning is
  issued, and the verdict is ``None``. Fail open — and the gap is on the
  record as a warning, not hidden.
"""
from __future__ import annotations

import functools
import warnings
from typing import Any, Callable, Optional, Tuple

from .client import GateClient, Verdict, VerityError


class GateVeto(Exception):
    """Enforce mode: the gate vetoed the proposal; the function did not run."""

    def __init__(self, verdict: Verdict) -> None:
        super().__init__(
            f"gate VETO (rule: {verdict.rule}, chain seq: {verdict.seq})"
        )
        self.verdict = verdict


class GateEscalation(Exception):
    """Enforce mode: the gate escalated and no callback approved the call."""

    def __init__(self, verdict: Verdict) -> None:
        super().__init__(
            f"gate ESCALATE (rule: {verdict.rule}, chain seq: {verdict.seq})"
        )
        self.verdict = verdict


def check(
    client: GateClient,
    *,
    actor: str,
    action: str,
    consequence_class: str,
    target: Optional[str] = None,
    amount_usd: Optional[float] = None,
    mode: str = "shadow",
    on_escalate: Optional[Callable[[Verdict], bool]] = None,
) -> Optional[Verdict]:
    """Submit one proposal and decide whether execution may proceed.

    Returns the :class:`Verdict` when execution may proceed — or ``None``
    in shadow mode when the gate could not be reached. In enforce mode,
    raises :class:`GateVeto`, :class:`GateEscalation`, or
    :class:`VerityError` when execution may not proceed.
    """
    if mode not in ("shadow", "enforce"):
        raise ValueError(f"mode must be 'shadow' or 'enforce', got {mode!r}")
    try:
        v = client.verdict(
            actor=actor,
            action=action,
            consequence_class=consequence_class,
            target=target,
            amount_usd=amount_usd,
        )
    except VerityError:
        if mode == "enforce":
            raise  # fail closed: no verdict, no execution
        warnings.warn(
            "verity_gate: gate unreachable in shadow mode; "
            "proceeding without a verdict",
            RuntimeWarning,
            stacklevel=2,
        )
        return None  # fail open: the watch never breaks the work
    if mode == "shadow":
        return v
    if v.allowed:
        return v
    if v.vetoed:
        raise GateVeto(v)
    if v.escalated:
        if on_escalate is not None and on_escalate(v):
            return v
        raise GateEscalation(v)
    raise VerityError(f"unrecognized verdict from the gate: {v.verdict!r}", body=v.raw)


def guarded(
    client: GateClient,
    *,
    actor: str,
    action: str,
    consequence_class: str,
    target: Optional[str] = None,
    amount_usd: Optional[float] = None,
    mode: str = "shadow",
    on_escalate: Optional[Callable[[Verdict], bool]] = None,
) -> Callable:
    """Decorator form: gate a function as one recurring proposal.

    The proposal is fixed at decoration time — actor, action,
    consequence class, and optionally target and amount. In shadow mode
    the wrapped call returns ``(result, verdict)``; in enforce mode it
    returns ``result``, or raises before running.
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            v = check(
                client,
                actor=actor,
                action=action,
                consequence_class=consequence_class,
                target=target,
                amount_usd=amount_usd,
                mode=mode,
                on_escalate=on_escalate,
            )
            result = fn(*args, **kwargs)
            return (result, v) if mode == "shadow" else result

        return wrapper

    return decorator


def call(
    client: GateClient,
    fn: Callable,
    *args: Any,
    actor: str,
    action: str,
    consequence_class: str,
    target: Optional[str] = None,
    amount_usd: Optional[float] = None,
    mode: str = "shadow",
    on_escalate: Optional[Callable[[Verdict], bool]] = None,
    **kwargs: Any,
) -> Any:
    """Functional form of :func:`guarded`: gate ``fn(*args, **kwargs)`` once.

    Same return contract: ``(result, verdict)`` in shadow mode, ``result``
    in enforce mode.
    """
    v = check(
        client,
        actor=actor,
        action=action,
        consequence_class=consequence_class,
        target=target,
        amount_usd=amount_usd,
        mode=mode,
        on_escalate=on_escalate,
    )
    result = fn(*args, **kwargs)
    return (result, v) if mode == "shadow" else result
