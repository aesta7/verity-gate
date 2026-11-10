// verity-demo-worker — a standalone Cloudflare Worker for the /start/
// live demo. Attach it with the route:  verityverdict.com/api-demo/*
//
// It does exactly what the Pages Function version did: holds the demo
// key as a Worker secret (VERITY_DEMO_KEY), forwards nothing a visitor
// sends, and fires only the six fixed canary proposals at the gate.
// The burst carries a 75-second cooldown because the gate's velocity
// rule counts reads per caller inside a one-minute window and the demo
// key is one caller shared by every visitor.
const GATE = "https://api.verityverdict.com/api/v1/verdict";
const ACTOR = "canary";

const SINGLES = [
  { label: "fetch order status", expected: "ALLOW",
    proposal: { actor: ACTOR, action: "fetch order status", consequence_class: "read", target: "canary-test order #0001" } },
  { label: "purge all backups", expected: "VETO",
    proposal: { actor: ACTOR, action: "purge all backups", consequence_class: "destructive", target: "canary-test backup volume" } },
  { label: "send payout, $5,000", expected: "ESCALATE",
    proposal: { actor: ACTOR, action: "send payout", consequence_class: "money", amount_usd: 5000, target: "canary-test vendor acct" } },
  { label: "read config file — /etc/passwd", expected: "ESCALATE",
    proposal: { actor: ACTOR, action: "read config file", consequence_class: "access", target: "/etc/passwd" } },
  { label: "delete user records", expected: "ESCALATE",
    proposal: { actor: ACTOR, action: "delete user records", consequence_class: "write", target: "canary-test customer table" } },
];
const BURST_N = 35;
const BURST_PROPOSAL = { actor: ACTOR, action: "read inventory levels", consequence_class: "read" };
const COOLDOWN_MS = 75000;

let lastBurstAt = 0;
let burstBusy = false;

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

async function callGate(key, proposal) {
  const r = await fetch(GATE, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + key,
      "Content-Type": "application/json",
      "User-Agent": "verity-site-demo",
    },
    body: JSON.stringify(proposal),
  });
  const body = await r.json().catch(function () { return {}; });
  if (!r.ok) throw new Error(body.error || "gate " + r.status);
  return {
    verdict: body.verdict,
    rule: body.rule || (Array.isArray(body.rule_hits) ? body.rule_hits[0] : null),
    seq: body.seq != null ? body.seq : body.chain_seq != null ? body.chain_seq : null,
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/api-demo/canary") return json({ error: "not_found" }, 404);
    if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

    const key = env.VERITY_DEMO_KEY;
    if (!key) return json({ error: "demo_not_configured" }, 503);

    let part = "singles";
    try {
      const b = await request.json();
      if (b && b.part === "burst") part = "burst";
    } catch (e) { /* empty body = singles */ }

    try {
      if (part === "singles") {
        // Capture the chain head first: after firing, the public
        // preview is polled until this run's own records appear, so the
        // seal numbers shown are this run's — the preview can lag a
        // beat behind the gate, and it returns records oldest-first.
        let before = 0;
        try {
          const pv0 = await fetch("https://api.verityverdict.com/api/v1/chain/preview?limit=1");
          const d0 = await pv0.json();
          before = (d0.head && d0.head.seq) || 0;
        } catch (e) { /* seqs stay best-effort */ }
        const results = [];
        for (const s of SINGLES) {
          const v = await callGate(key, s.proposal);
          results.push({ label: s.label, expected: s.expected, verdict: v.verdict, rule: v.rule, seq: v.seq });
        }
        try {
          for (let attempt = 0; attempt < 5; attempt++) {
            const pv = await fetch("https://api.verityverdict.com/api/v1/chain/preview?limit=12");
            const data = await pv.json();
            const fresh = (data.records || []).filter(function (r) {
              return String(r.caller || "").indexOf("demo") === 0 && r.seq > before;
            });
            if (fresh.length >= results.length) {
              fresh.slice(0, results.length).forEach(function (r, i) { results[i].seq = r.seq; });
              break;
            }
            await new Promise(function (res) { setTimeout(res, 700); });
          }
        } catch (e) { /* seqs stay null; verdicts are unaffected */ }
        return json({ part: part, results: results });
      }

    const now = Date.now();
      const waitS = Math.ceil((lastBurstAt + COOLDOWN_MS - now) / 1000);
      if (burstBusy || waitS > 0) {
        return json({ error: "cooldown", retry_after_s: burstBusy ? 30 : waitS }, 429);
      }
      burstBusy = true;
      lastBurstAt = now;
      try {
        const verdicts = [];
        for (let i = 0; i < BURST_N; i++) verdicts.push(await callGate(key, BURST_PROPOSAL));
        const esc = verdicts.filter(function (v) { return v.verdict === "ESCALATE"; }).length;
        const allow = verdicts.filter(function (v) { return v.verdict === "ALLOW"; }).length;
        const firstEsc = verdicts.findIndex(function (v) { return v.verdict === "ESCALATE"; });
        return json({
          part: part, total: BURST_N, allow: allow, escalate: esc,
          first_escalation_at: firstEsc >= 0 ? firstEsc + 1 : null,
          last_seq: verdicts[verdicts.length - 1].seq,
        });
      } finally {
        burstBusy = false;
      }
    } catch (e) {
      return json({ error: "gate_error", detail: String((e && e.message) || e) }, 502);
    }
  },
};
