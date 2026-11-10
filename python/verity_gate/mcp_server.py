"""An MCP server for the Verity gate — the gate as a tool the host can load.

Run it under any MCP host (Claude Desktop, Claude Code, Cursor, and the
rest) and the gate appears as tools in the agent's own toolbox:

    verity_verdict        submit a proposed action; get ALLOW, VETO, or
                          ESCALATE, the rule that decided it, and the
                          record's place in the audit chain
    verity_attest         seal a signed attestation of standing intent
                          (purpose + declared domains) before verdicts
    verity_chain_verify   replay the audit chain and confirm every link
    verity_health         service status; needs no key

The caller key comes from the operator, through the environment — never
from the agent, and never from a tool argument:

    VERITY_GATE_KEY        a key the operator claimed at
                           https://verityverdict.com/start/ (free,
                           shadow-only) or took at checkout (enforcement)
    VERITY_GATE_BASE_URL   optional; defaults to the production gate

Registration with a host is configuration, not code — for example:

    {
      "mcpServers": {
        "verity-gate": {
          "command": "verity-gate-mcp",
          "env": { "VERITY_GATE_KEY": "vk_..." }
        }
      }
    }

Standard library only, like the rest of the package. The transport is
newline-delimited JSON-RPC over stdio, per the MCP specification.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

from .client import BASE_URL, GateClient, VerityError

PROTOCOL_VERSION = "2025-03-26"
SERVER_INFO = {"name": "verity-gate", "version": "0.2.1"}

TOOLS = [
    {
        "name": "verity_verdict",
        "description": (
            "Submit one proposed action to the Verity gate BEFORE executing "
            "it, and act on the verdict returned. The gate answers ALLOW, "
            "VETO, or ESCALATE, names the rule that decided it, and seals "
            "the verdict into a hash-chained audit record. Use this for any "
            "action with consequences outside the conversation: writes, "
            "deletions, payments, messages, access changes, commands."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "actor": {
                    "type": "string",
                    "description": "The identity proposing the action (agent or component name).",
                },
                "action": {
                    "type": "string",
                    "description": "The proposed action, in plain language: 'read a customer record', 'send payout', 'purge all backups'.",
                },
                "consequence_class": {
                    "type": "string",
                    "description": "What the action touches: read, write, money, access, destructive, or the closest fit.",
                },
                "target": {
                    "type": "string",
                    "description": "Optional: what the action acts on (a record, an account, a path).",
                },
                "amount_usd": {
                    "type": "number",
                    "description": "Optional: the amount at stake, for money actions.",
                },
            },
            "required": ["actor", "action", "consequence_class"],
        },
    },
    {
        "name": "verity_attest",
        "description": (
            "Seal a signed attestation of standing intent into the chain: "
            "the caller's purpose and the domains it will act in. Some "
            "callers are refused verdicts until they have attested."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "purpose": {"type": "string"},
                "domains": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["purpose", "domains"],
        },
    },
    {
        "name": "verity_chain_verify",
        "description": (
            "Replay the audit chain from the first record and confirm every "
            "link — the history is verifiable, not asserted."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "verity_health",
        "description": "Gate service status, and whether the chain database is bound. Needs no key.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

_NO_KEY = (
    "No caller key is configured. Verity keys are provisioned by the "
    "operator, never by the agent: ask your operator to claim a free "
    "shadow key at https://verityverdict.com/start/ and set it as "
    "VERITY_GATE_KEY in this server's environment."
)


def _client() -> Optional[GateClient]:
    key = os.environ.get("VERITY_GATE_KEY", "").strip()
    if not key:
        return None
    base = os.environ.get("VERITY_GATE_BASE_URL", BASE_URL)
    return GateClient(key, base_url=base)


def _text(payload: Any, *, is_error: bool = False) -> Dict[str, Any]:
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Execute one tool call. Never raises — errors come back as results."""
    client = _client()
    try:
        if name == "verity_health":
            probe = client or GateClient("", base_url=os.environ.get("VERITY_GATE_BASE_URL", BASE_URL))
            return _text(probe.health())
        if client is None:
            return _text(_NO_KEY, is_error=True)
        if name == "verity_verdict":
            v = client.verdict(
                actor=str(arguments.get("actor", "")),
                action=str(arguments.get("action", "")),
                consequence_class=str(arguments.get("consequence_class", "")),
                target=arguments.get("target"),
                amount_usd=arguments.get("amount_usd"),
            )
            return _text(
                {
                    "verdict": v.verdict,
                    "rule": v.rule,
                    "seq": v.seq,
                    "chain_hash": v.chain_hash,
                    "signature": v.signature,
                }
            )
        if name == "verity_attest":
            return _text(
                client.attest(
                    purpose=str(arguments.get("purpose", "")),
                    domains=list(arguments.get("domains") or []),
                )
            )
        if name == "verity_chain_verify":
            return _text(client.verify_chain())
        return _text(f"unknown tool: {name}", is_error=True)
    except VerityError as exc:
        return _text(f"the gate refused or could not be reached: {exc}", is_error=True)
    except Exception as exc:  # a tool error must never kill the server
        return _text(f"internal error: {exc}", is_error=True)


def handle(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Handle one JSON-RPC message; None means 'notification, no reply'."""
    method = message.get("method", "")
    msg_id = message.get("id")
    if method == "initialize":
        params = message.get("params") or {}
        version = params.get("protocolVersion") or PROTOCOL_VERSION
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        }
    if method.startswith("notifications/"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = message.get("params") or {}
        result = call_tool(str(params.get("name", "")), params.get("arguments") or {})
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}
    if msg_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(message, list):  # tolerate batches
            replies = [r for m in message if (r := handle(m)) is not None]
            for reply in replies:
                sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
            continue
        reply = handle(message)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
