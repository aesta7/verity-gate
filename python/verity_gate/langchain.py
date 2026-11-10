"""LangChain integration: wrap a tool so every invocation crosses the gate.

Optional. Importing this module never requires LangChain to be installed;
constructing :class:`VerityGatedTool` without it raises an ImportError
that names the fix.

The wrapped tool's name and each invocation's input form the proposal.
Mode and failure semantics are the same as :mod:`verity_gate.guard`:

- ``shadow``: the tool always runs; the verdict is kept on
  ``last_verdict`` for inspection.
- ``enforce``: the tool runs only on ALLOW (or on an ESCALATE your
  ``on_escalate`` callback approves). VETO and unapproved ESCALATE raise,
  and a gate failure fails closed — the tool does not run.
"""
from __future__ import annotations

from typing import Any

from .guard import check

try:  # langchain-core is the current home of BaseTool
    from langchain_core.tools import BaseTool as _BaseTool
except ImportError:  # pragma: no cover - depends on the installed version
    try:
        from langchain.tools import BaseTool as _BaseTool
    except ImportError:
        _BaseTool = None

_INSTALL_MSG = (
    "VerityGatedTool requires LangChain, which is not installed. "
    "Install it with `pip install langchain-core`, "
    "or `pip install 'verity-gate[langchain]'`."
)


if _BaseTool is not None:

    class VerityGatedTool(_BaseTool):
        """A LangChain tool with the Verity gate in front of it.

        >>> gated = VerityGatedTool(inner_tool, client, mode="shadow")
        Drop ``gated`` into the agent's tool list in place of the original.
        """

        name: str
        description: str
        inner: Any = None
        client: Any = None
        actor: str = "langchain-agent"
        consequence_class: str = "write"
        mode: str = "shadow"
        on_escalate: Any = None
        last_verdict: Any = None

        def __init__(
            self,
            inner: Any,
            client: Any,
            *,
            actor: str = "langchain-agent",
            consequence_class: str = "write",
            mode: str = "shadow",
            on_escalate: Any = None,
            **kwargs: Any,
        ) -> None:
            super().__init__(
                name=inner.name,
                description=inner.description,
                inner=inner,
                client=client,
                actor=actor,
                consequence_class=consequence_class,
                mode=mode,
                on_escalate=on_escalate,
                **kwargs,
            )

        def _propose(self, tool_input: Any) -> None:
            action = f"{self.inner.name}: {tool_input}"
            self.last_verdict = check(
                self.client,
                actor=self.actor,
                action=action,
                consequence_class=self.consequence_class,
                target=str(tool_input),
                mode=self.mode,
                on_escalate=self.on_escalate,
            )

        def _run(self, tool_input: Any = "", **kwargs: Any) -> Any:
            self._propose(tool_input)
            return self.inner._run(tool_input, **kwargs)

        async def _arun(self, tool_input: Any = "", **kwargs: Any) -> Any:
            self._propose(tool_input)
            return await self.inner._arun(tool_input, **kwargs)

else:

    class VerityGatedTool:  # type: ignore[no-redef]
        """Placeholder used when LangChain is not installed."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(_INSTALL_MSG)
