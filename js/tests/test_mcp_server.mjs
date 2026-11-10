/**
 * Protocol tests for the JS MCP server (../verity-mcp.mjs).
 *
 * Stands up a stub gate on a local port, then speaks real newline-delimited
 * JSON-RPC to the server running as a subprocess — the same way an MCP host
 * would. Offline: nothing leaves the machine.
 *
 * Run:  node tests/test_mcp_server.mjs
 */
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const SERVER = join(here, "..", "verity-mcp.mjs");

let failures = 0;
function check(label, cond) {
  if (cond) console.log(`PASS ${label}`);
  else {
    failures++;
    console.log(`FAIL ${label}`);
  }
}

const stub = createServer((req, res) => {
  const send = (obj, status = 200) => {
    const body = JSON.stringify(obj);
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(body);
  };
  if (req.url.endsWith("/health")) return send({ ok: true, mode: "shadow", chain_bound: true });
  if (req.url.endsWith("/chain/verify")) return send({ ok: true, records: 18 });
  if (req.url.endsWith("/verdict") && req.method === "POST") {
    if (req.headers.authorization !== "Bearer vk_test") return send({ error: "unauthorized" }, 401);
    return send({ verdict: "VETO", rule: "R1", seq: 19, chain_hash: "abc123", signature: "sig456" });
  }
  return send({ error: "not_found" }, 404);
});
await new Promise((r) => stub.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${stub.address().port}/api/v1`;

class Session {
  constructor(env) {
    this.proc = spawn(process.execPath, [SERVER], { env, stdio: ["pipe", "pipe", "inherit"] });
    this.lines = createInterface({ input: this.proc.stdout });
    this.pending = [];
    this.waiters = [];
    this.lines.on("line", (line) => {
      const msg = JSON.parse(line);
      const w = this.waiters.shift();
      if (w) w(msg);
      else this.pending.push(msg);
    });
    this.id = 0;
  }
  next() {
    if (this.pending.length) return Promise.resolve(this.pending.shift());
    return new Promise((r) => this.waiters.push(r));
  }
  async send(method, params, notify = false) {
    this.id += 1;
    const msg = { jsonrpc: "2.0", method };
    if (!notify) msg.id = this.id;
    if (params !== undefined) msg.params = params;
    this.proc.stdin.write(JSON.stringify(msg) + "\n");
    if (notify) return null;
    return this.next();
  }
  close() {
    this.proc.stdin.end();
    this.proc.kill();
  }
}

// --- session with a key -------------------------------------------------
{
  const env = { ...process.env, VERITY_GATE_KEY: "vk_test", VERITY_GATE_BASE_URL: base };
  const s = new Session(env);
  const init = await s.send("initialize", { protocolVersion: "2025-03-26" });
  check("initialize serverInfo", init.result.serverInfo.name === "verity-gate");
  check("initialize version echo", init.result.protocolVersion === "2025-03-26");
  await s.send("notifications/initialized", undefined, true);

  const listed = await s.send("tools/list");
  const names = listed.result.tools.map((t) => t.name);
  check(
    "tools/list",
    JSON.stringify(names) ===
      JSON.stringify(["verity_verdict", "verity_attest", "verity_chain_verify", "verity_health"])
  );

  const call = await s.send("tools/call", {
    name: "verity_verdict",
    arguments: { actor: "test-agent", action: "purge all backups", consequence_class: "destructive" },
  });
  const payload = JSON.parse(call.result.content[0].text);
  check("verdict call ok", call.result.isError === false);
  check("verdict payload", payload.verdict === "VETO" && payload.rule === "R1" && payload.seq === 19);

  const health = await s.send("tools/call", { name: "verity_health", arguments: {} });
  check("health", JSON.parse(health.result.content[0].text).ok === true);

  const ping = await s.send("ping");
  check("ping", JSON.stringify(ping.result) === "{}");

  const unknown = await s.send("tools/call", { name: "nope", arguments: {} });
  check("unknown tool isError", unknown.result.isError === true);
  s.close();
}

// --- session without a key ----------------------------------------------
{
  const env = { ...process.env };
  delete env.VERITY_GATE_KEY;
  const s = new Session(env);
  await s.send("initialize", { protocolVersion: "2025-03-26" });
  const call = await s.send("tools/call", {
    name: "verity_verdict",
    arguments: { actor: "a", action: "read a record", consequence_class: "read" },
  });
  check("no-key isError", call.result.isError === true);
  check("no-key guidance", call.result.content[0].text.includes("verityverdict.com/start/"));
  s.close();
}

stub.close();
console.log(failures === 0 ? "ALL PASSED" : `${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
