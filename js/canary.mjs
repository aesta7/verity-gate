/**
 * canary.mjs — the six canary checks.
 *
 * An adopter runs these against the live gate with their own caller key
 * and watches the rules fire: one clean read allowed, one destructive
 * action vetoed, three escalations, and a velocity burst that trips the
 * rate rule part-way through. Mirrors python/verity_gate/canary.py.
 */
const ACTOR = "canary";

const SINGLES = [
  ["read the canary order",
   { actor: ACTOR, action: "fetch order status", consequence_class: "read", target: "canary-test order #0001" }, "ALLOW"],
  ["purge all backups",
   { actor: ACTOR, action: "purge all backups", consequence_class: "destructive", target: "canary-test backup volume" }, "VETO"],
  ["send a $5,000 payout",
   { actor: ACTOR, action: "send payout", consequence_class: "money", amount_usd: 5000, target: "canary-test vendor acct" }, "ESCALATE"],
  ["read /etc/passwd",
   { actor: ACTOR, action: "read config file", consequence_class: "access", target: "/etc/passwd" }, "ESCALATE"],
  ["delete user records",
   { actor: ACTOR, action: "delete user records", consequence_class: "write", target: "canary-test customer table" }, "ESCALATE"],
];

const BURST_COUNT = 35;
const BURST_PROPOSAL = { actor: ACTOR, action: "read inventory levels", consequence_class: "read" };

/** Fire all six canaries. Returns { ok, lines }. */
export async function runCanary(client) {
  const lines = [];
  let ok = true;
  for (let i = 0; i < SINGLES.length; i++) {
    const [label, proposal, expected] = SINGLES[i];
    const v = await client.verdict(proposal);
    const passed = v.verdict === expected;
    ok = ok && passed;
    lines.push(
      `canary ${i + 1}/6  ${label.padEnd(24)} -> ${String(v.verdict).padEnd(8)} ` +
      `(expected ${expected}; rule ${v.rule}; seq ${v.seq})  ${passed ? "PASS" : "FAIL"}`
    );
  }
  const verdicts = [];
  for (let i = 0; i < BURST_COUNT; i++) verdicts.push((await client.verdict(BURST_PROPOSAL)).verdict);
  const escalations = verdicts.filter((x) => x === "ESCALATE").length;
  const allows = verdicts.filter((x) => x === "ALLOW").length;
  const passed = escalations >= 1;
  ok = ok && passed;
  lines.push(
    `canary 6/6  ${BURST_COUNT} reads in a burst        -> ${allows} ALLOW, ${escalations} ESCALATE ` +
    `(expected ESCALATE on late rows)  ${passed ? "PASS" : "FAIL"}`
  );
  return { ok, lines };
}
