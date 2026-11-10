/** Offline test for the JS canary CLI against an in-process fake gate. */
import http from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.join(here, "..", "verity-cli.mjs");

let seq = 100;
const reads = {};
const server = http.createServer((req, res) => {
  let data = "";
  req.on("data", (c) => (data += c));
  req.on("end", () => {
    const body = JSON.parse(data || "{}");
    const action = (body.action || "").toLowerCase();
    const cls = body.consequence_class || "";
    seq += 1;
    let verdict = "ALLOW", rule = null;
    if (action.includes("purge") || cls === "destructive") { verdict = "VETO"; rule = "R1"; }
    else if (cls === "money" || (body.amount_usd || 0) > 0) { verdict = "ESCALATE"; rule = "R2"; }
    else if (body.target === "/etc/passwd") { verdict = "ESCALATE"; rule = "R4_denylist"; }
    else if (action.startsWith("delete")) { verdict = "ESCALATE"; rule = "R4_delete_language"; }
    else if (cls === "read") {
      const n = (reads[body.actor] = (reads[body.actor] || 0) + 1);
      if (n > 30) { verdict = "ESCALATE"; rule = "R3"; }
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ verdict, rule_hits: rule ? [rule] : [], seq }));
  });
});

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}/api/v1`;

function run(args, env) {
  return new Promise((resolve) => {
    const p = spawn("node", [cli, ...args], { env: { ...process.env, ...env } });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => resolve({ code, out, err }));
  });
}

let passed = 0, total = 0;
const check = (name, cond, extra = "") => { total++; if (cond) { passed++; console.log(`ok - ${name}`); } else console.log(`FAIL - ${name} ${extra}`); };

const good = await run(["canary"], { VERITY_GATE_KEY: "vk_test", VERITY_GATE_BASE_URL: base });
check("canary exits 0 against fake gate", good.code === 0, `code=${good.code} err=${good.err}`);
check("report shows VETO line", good.out.includes("VETO"));
check("report shows burst ESCALATE", /ALLOW, \d+ ESCALATE/.test(good.out));
check("report ends all passed", good.out.includes("all checks passed"));

const nokey = await run(["canary"], { VERITY_GATE_KEY: "", VERITY_GATE_BASE_URL: base });
check("no key exits 2 with guidance", nokey.code === 2 && nokey.err.includes("verityverdict.com/start"), `code=${nokey.code}`);

server.close();
console.log(`${passed}/${total} passed`);
process.exitCode = passed === total ? 0 : 1;
