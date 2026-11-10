"""Protocol tests for the MCP server (verity_gate.mcp_server).

Stands up a stub gate on a local port, then speaks real newline-delimited
JSON-RPC to the server running as a subprocess — the same way an MCP host
would. Offline: nothing leaves the machine.

Runnable under pytest or standalone:  python3 tests/test_mcp_server.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

VERDICT_BODY = {
    "verdict": "VETO",
    "rule": "R1",
    "seq": 19,
    "chain_hash": "abc123",
    "signature": "sig456",
}


class StubGate(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _send(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.endswith("/health"):
            return self._send({"ok": True, "mode": "shadow", "chain_bound": True})
        if self.path.endswith("/chain/verify"):
            return self._send({"ok": True, "records": 18})
        return self._send({"error": "not_found"}, 404)

    def do_POST(self):
        if self.path.endswith("/verdict"):
            if self.headers.get("Authorization") != "Bearer vk_test":
                return self._send({"error": "unauthorized"}, 401)
            return self._send(VERDICT_BODY)
        return self._send({"error": "not_found"}, 404)


class McpSession:
    def __init__(self, env_extra):
        env = dict(os.environ)
        env.update(env_extra)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "verity_gate.mcp_server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env=env,
            text=True,
        )
        self._id = 0

    def send(self, method, params=None, notify=False):
        self._id += 1
        msg = {"jsonrpc": "2.0", "method": method}
        if not notify:
            msg["id"] = self._id
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        if notify:
            return None
        line = self.proc.stdout.readline()
        assert line, f"no reply to {method}"
        return json.loads(line)

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def run_session(env_extra, checks):
    session = McpSession(env_extra)
    try:
        return checks(session)
    finally:
        session.close()


def test_protocol_and_tools():
    stub = ThreadingHTTPServer(("127.0.0.1", 0), StubGate)
    port = stub.server_address[1]
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}/api/v1"

    def checks(s):
        init = s.send("initialize", {"protocolVersion": "2025-03-26"})
        assert init["result"]["serverInfo"]["name"] == "verity-gate"
        assert init["result"]["protocolVersion"] == "2025-03-26"
        s.send("notifications/initialized", notify=True)

        listed = s.send("tools/list")
        names = [t["name"] for t in listed["result"]["tools"]]
        assert names == [
            "verity_verdict",
            "verity_attest",
            "verity_chain_verify",
            "verity_health",
        ], names

        call = s.send(
            "tools/call",
            {
                "name": "verity_verdict",
                "arguments": {
                    "actor": "test-agent",
                    "action": "purge all backups",
                    "consequence_class": "destructive",
                },
            },
        )
        result = call["result"]
        assert result["isError"] is False
        payload = json.loads(result["content"][0]["text"])
        assert payload["verdict"] == "VETO" and payload["rule"] == "R1"
        assert payload["seq"] == 19

        health = s.send("tools/call", {"name": "verity_health", "arguments": {}})
        assert json.loads(health["result"]["content"][0]["text"])["ok"] is True

        ping = s.send("ping")
        assert ping["result"] == {}

        unknown = s.send("tools/call", {"name": "nope", "arguments": {}})
        assert unknown["result"]["isError"] is True

    try:
        run_session(
            {"VERITY_GATE_KEY": "vk_test", "VERITY_GATE_BASE_URL": base}, checks
        )
    finally:
        stub.shutdown()


def test_no_key_guidance():
    def checks(s):
        s.send("initialize", {"protocolVersion": "2025-03-26"})
        call = s.send(
            "tools/call",
            {
                "name": "verity_verdict",
                "arguments": {
                    "actor": "a",
                    "action": "read a record",
                    "consequence_class": "read",
                },
            },
        )
        result = call["result"]
        assert result["isError"] is True
        assert "verityverdict.com/start/" in result["content"][0]["text"]

    env = dict(os.environ)
    env.pop("VERITY_GATE_KEY", None)
    # run with only the no-key environment (no base URL override needed:
    # the call must fail before any network use)
    session = McpSession.__new__(McpSession)
    session.proc = subprocess.Popen(
        [sys.executable, "-m", "verity_gate.mcp_server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        env={k: v for k, v in env.items() if k != "VERITY_GATE_KEY"},
        text=True,
    )
    session._id = 0
    try:
        checks(session)
    finally:
        session.close()


if __name__ == "__main__":
    test_protocol_and_tools()
    print("PASS test_protocol_and_tools")
    test_no_key_guidance()
    print("PASS test_no_key_guidance")
    print("2/2 passed")
