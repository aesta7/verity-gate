#!/usr/bin/env node
/**
 * An MCP server for the Verity gate — the gate as a tool the host can load.
 *
 * Run it under any MCP host (Claude Desktop, Claude Code, Cursor, and the
 * rest) and the gate appears as tools in the agent's own toolbox:
 *
 *   verity_verdict        submit a proposed action; get ALLOW, VETO, or
 *                         ESCALATE, the rule that decided it, and the
 *                         record's place in the audit chain
 *   verity_attest         seal a signed attestation of standing intent
 *                         (purpose + declared domains) before verdicts
 *   verity_chain_verify   replay the audit chain and confirm every link
 *   verity_health         service status; needs no key
 *
 * The caller key comes from the operator, through the environment — never
 * from the agent, and never from a tool argument:
 *
 *   VERITY_GATE_KEY        a key the operator claimed at
 *                          https://verityverdict.com/start/ (free,
 *                          shadow-only) or took at checkout (enforcement)
 *   VERITY_GATE_BASE_URL   optional; defaults to the production gate
 *
 * Registration with a host is configuration, not code — for example:
 *
 *   {
 *     "mcpServers": {
 *       "verity-gate": {
 *         "command": "npx",
 *         "args": ["-y", "verity-gate-mcp"],
 *         "env": { "VERITY_GATE_KEY": "vk_..." }
 *       }
 *     }
 *   }
 *
 * (Installing the verity-gate npm package also puts a `verity-gate-mcp`
 * binary on the path, which can be the command directly.)
 *
 * No dependencies. The transport is newline-delimited JSON-RPC over
 * stdio, per the MCP specification.
 */
import { createInterface } from "node:readline";
import { BASE_URL, GateClient } from "./verity.mjs";

const PROTOCOL_VERSION = "2025-03-26";
const SERVER_INFO = { name: "verity-gate", version: "0.2.1" };

const TOOLS = [
  {
    name: "verity_verdict",
    description:
      "Submit one proposed action to the Verity gate BEFORE executing " +
      "it, and act on the verdict returned. The gate answers ALLOW, " +
      "VETO, or ESCALATE, names the rule that decided it, and seals " +
      "the verdict into a hash-chained audit record. Use this for any " +
      "action with consequences outside the conversation: writes, " +
      "deletions, payments, messages, access changes, commands.",
    inputSchema: {
      type: "object",
      properties: {
        actor: {
          type: "string",
          description: "The identity proposing the action (agent or component name).",
        },
        action: {
          type: "string",
          description:
            "The proposed action, in plain language: 'read a customer record', 'send payout', 'purge all backups'.",
        },
        consequence_class: {
          type: "string",
          description: "What the action touches: read, write, money, access, destructive, or the closest fit.",
        },
        target: {
          type: "string",
          description: "Optional: what the action acts on (a record, an account, a path).",
        },
        amount_usd: {
          type: "number",
          description: "Optional: the amount at stake, for money actions.",
        },
      },
      required: ["actor", "action", "consequence_class"],
    },
  },
  {
    name: "verity_attest",
    description:
      "Seal a signed attestation of standing intent into the chain: " +
      "the caller's purpose and the domains it will act in. Some " +
      "callers are refused verdicts until they have attested.",
    inputSchema: {
      type: "object",
      properties: {
        purpose: { type: "string" },
        domains: { type: "array", items: { type: "string" } },
      },
      required: ["purpose", "domains"],
    },
  },
  {
    name: "verity_chain_verify",
    description:
      "Replay the audit chain from the first record and confirm every " +
      "link — the history is verifiable, not asserted.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "verity_health",
    description: "Gate service status, and whether the chain database is bound. Needs no key.",
    inputSchema: { type: "object", properties: {} },
  },
];

const NO_KEY =
  "No caller key is configured. Verity keys are provisioned by the " +
  "operator, never by the agent: ask your operator to claim a free " +
  "shadow key at https://verityverdict.com/start/ and set it as " +
  "VERITY_GATE_KEY in this server's environment.";

function client() {
  const key = (process.env.VERITY_GATE_KEY || "").trim();
  if (!key) return null;
  return new GateClient(key, { baseUrl: process.env.VERITY_GATE_BASE_URL || BASE_URL });
}

function text(payload, isError = false) {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  return { content: [{ type: "text", text: body }], isError };
}

export async function callTool(name, args = {}) {
  const gate = client();
  try {
    if (name === "verity_health") {
      const probe = gate ?? new GateClient("", { baseUrl: process.env.VERITY_GATE_BASE_URL || BASE_URL });
      return text(await probe.health());
    }
    if (!gate) return text(NO_KEY, true);
    if (name === "verity_verdict") {
      const v = await gate.verdict({
        actor: String(args.actor ?? ""),
        action: String(args.action ?? ""),
        consequence_class: String(args.consequence_class ?? ""),
        target: args.target ?? undefined,
        amount_usd: args.amount_usd ?? undefined,
      });
      return text({
        verdict: v.verdict,
        rule: v.rule,
        seq: v.seq,
        chain_hash: v.chainHash,
        signature: v.signature,
      });
    }
    if (name === "verity_attest") {
      return text(await gate.attest(String(args.purpose ?? ""), args.domains ?? []));
    }
    if (name === "verity_chain_verify") {
      return text(await gate.verifyChain());
    }
    return text(`unknown tool: ${name}`, true);
  } catch (err) {
    return text(`the gate refused or could not be reached: ${err.message}`, true);
  }
}

export async function handle(message) {
  const method = message.method || "";
  const id = message.id;
  if (method === "initialize") {
    const version = message.params?.protocolVersion || PROTOCOL_VERSION;
    return {
      jsonrpc: "2.0",
      id,
      result: { protocolVersion: version, capabilities: { tools: {} }, serverInfo: SERVER_INFO },
    };
  }
  if (method.startsWith("notifications/")) return null;
  if (method === "ping") return { jsonrpc: "2.0", id, result: {} };
  if (method === "tools/list") return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
  if (method === "tools/call") {
    const result = await callTool(message.params?.name || "", message.params?.arguments || {});
    return { jsonrpc: "2.0", id, result };
  }
  if (id === undefined || id === null) return null;
  return { jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } };
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const rl = createInterface({ input: process.stdin });
  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let message;
    try {
      message = JSON.parse(trimmed);
    } catch {
      return;
    }
    const messages = Array.isArray(message) ? message : [message];
    for (const m of messages) {
      const reply = await handle(m);
      if (reply !== null) process.stdout.write(JSON.stringify(reply) + "\n");
    }
  });
}
