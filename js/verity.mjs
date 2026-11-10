/**
 * verity.mjs — a client and integration helpers for the Verity Gate API.
 *
 * One file, no dependencies. Node 18+ or any runtime with global fetch.
 *
 * Every call carries the caller key as a bearer credential. Keys are
 * issued to a human operator, never to the agent itself: claim a free
 * shadow key at https://verityverdict.com/start/ (shown exactly once),
 * or take an enforcement key at checkout.
 *
 *   import { GateClient, guard } from "./verity.mjs";
 *   const client = new GateClient("vk_...");  // or new GateClient() to use $VERITY_GATE_KEY
 *   const [result, verdict] = await guard(client,
 *     { actor: "my-agent", action: "read a customer record", consequence_class: "read" },
 *     () => readRecord(42));  // shadow mode: always runs, verdict attached
 */

export const BASE_URL = "https://api.verityverdict.com/api/v1";

/** Any failure talking to the gate. Carries the HTTP status and body, when there are any. */
export class VerityError extends Error {
  constructor(message, { status = null, body = null } = {}) {
    super(message);
    this.name = "VerityError";
    this.status = status;
    this.body = body;
  }
}

/** HTTP 401 — the caller key was missing or not recognized. */
export class Unauthorized extends VerityError {
  constructor(body) {
    super("unauthorized", { status: 401, body });
    this.name = "Unauthorized";
  }
}

/** HTTP 402 — the caller's subscription is not in good standing. */
export class NotInGoodStanding extends VerityError {
  constructor(body) {
    super("caller_not_in_good_standing", { status: 402, body });
    this.name = "NotInGoodStanding";
  }
}

/** The gate refused the call: this caller must attest before verdicts. */
export class AttestationRequired extends VerityError {
  constructor(status, body) {
    super("attestation_required", { status, body });
    this.name = "AttestationRequired";
  }
}

/** Enforce mode: the gate vetoed the proposal; the function did not run. */
export class GateVeto extends Error {
  constructor(verdict) {
    super(`gate VETO (rule: ${verdict.rule}, chain seq: ${verdict.seq})`);
    this.name = "GateVeto";
    this.verdict = verdict;
  }
}

/** Enforce mode: the gate escalated and no callback approved the call. */
export class GateEscalation extends Error {
  constructor(verdict) {
    super(`gate ESCALATE (rule: ${verdict.rule}, chain seq: ${verdict.seq})`);
    this.name = "GateEscalation";
    this.verdict = verdict;
  }
}

/** One verdict from the gate, as returned by POST /verdict. */
export class Verdict {
  constructor({ verdict, rule = null, seq = null, chainHash = null, signature = null, raw = {} }) {
    this.verdict = verdict;
    this.rule = rule;
    this.seq = seq;
    this.chainHash = chainHash;
    this.signature = signature;
    this.raw = raw;
  }

  get allowed() { return this.verdict === "ALLOW"; }
  get vetoed() { return this.verdict === "VETO"; }
  get escalated() { return this.verdict === "ESCALATE"; }

  /**
   * Parse a verdict response defensively: the rule may arrive as `rule`,
   * `rule_id`, or the first entry of `rule_hits`; the chain sequence as
   * `seq` or `chain_seq`. The full body is kept on `raw` either way.
   */
  static fromBody(body) {
    body = body ?? {};
    const ruleHits = Array.isArray(body.rule_hits) ? body.rule_hits : [];
    return new Verdict({
      verdict: String(body.verdict ?? "").toUpperCase(),
      rule: body.rule ?? body.rule_id ?? (ruleHits.length ? ruleHits[0] : null),
      seq: body.seq ?? body.chain_seq ?? null,
      chainHash: body.chain_hash ?? null,
      signature: body.signature ?? null,
      raw: body,
    });
  }
}

export class GateClient {
  /**
   * @param {string} apiKey  A caller key claimed at verityverdict.com/start/
   * @param {object} [opts]
   * @param {string} [opts.baseUrl]
   * @param {number} [opts.timeoutMs]  Per-call timeout, default 10000.
   * @param {Function} [opts.fetchImpl]  Injectable fetch (for tests).
   */
  constructor(apiKey, { baseUrl, timeoutMs = 10000, fetchImpl = globalThis.fetch } = {}) {
    if (typeof fetchImpl !== "function") {
      throw new Error("verity: no fetch implementation available (Node 18+ required, or pass fetchImpl)");
    }
    // Zero-config: with no key argument, the key and base URL come from
    // the operator's environment (VERITY_GATE_KEY / VERITY_GATE_BASE_URL).
    const env = typeof process !== "undefined" && process.env ? process.env : {};
    this.apiKey = apiKey ?? env.VERITY_GATE_KEY;
    this.baseUrl = (baseUrl ?? env.VERITY_GATE_BASE_URL ?? BASE_URL).replace(/\/+$/, "");
    this.timeoutMs = timeoutMs;
    this._fetch = fetchImpl;
  }

  async #request(method, path, { payload, auth = true } = {}) {
    const headers = { Accept: "application/json" };
    if (auth && this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;
    const init = { method, headers };
    if (payload !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(payload);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    init.signal = controller.signal;
    let status, data;
    try {
      const resp = await this._fetch(this.baseUrl + path, init);
      status = resp.status;
      const text = await resp.text();
      try { data = text ? JSON.parse(text) : {}; }
      catch { data = { error: text }; }
    } catch (err) {
      if (err instanceof VerityError) throw err;
      throw new VerityError(`gate unreachable: ${err.message}`, {});
    } finally {
      clearTimeout(timer);
    }
    if (status === 401) throw new Unauthorized(data);
    if (status === 402) throw new NotInGoodStanding(data);
    if (status >= 400) {
      if (data && data.error === "attestation_required") throw new AttestationRequired(status, data);
      const detail = data && data.error ? `: ${data.error}` : "";
      throw new VerityError(`gate returned HTTP ${status}${detail}`, { status, body: data });
    }
    return data;
  }

  /** Submit one proposed action; resolves to a Verdict (ALLOW, VETO, or ESCALATE). */
  async verdict({ actor, action, consequence_class, consequenceClass, target, amount_usd, amountUsd } = {}) {
    const payload = {
      actor,
      action,
      consequence_class: consequence_class ?? consequenceClass,
    };
    if (target !== undefined) payload.target = target;
    const amount = amount_usd ?? amountUsd;
    if (amount !== undefined) payload.amount_usd = amount;
    return Verdict.fromBody(await this.#request("POST", "/verdict", { payload }));
  }

  /** Seal a signed attestation of standing intent (purpose + declared domains) into the chain. */
  async attest(purpose, domains) {
    return this.#request("POST", "/attest", { payload: { purpose, domains: [...domains] } });
  }

  /** Revoke this caller's attestation; the revocation is itself sealed. */
  async revokeAttestation() {
    return this.#request("POST", "/attest/revoke", { payload: {} });
  }

  /** Read the audit chain back — metadata only, no proposal contents. */
  async chain(limit) {
    return this.#request("GET", "/chain" + (limit != null ? `?limit=${Number(limit) | 0}` : ""));
  }

  /** Replay the chain from the first record and confirm every link. */
  async verifyChain() {
    return this.#request("GET", "/chain/verify");
  }

  /** The gate's Ed25519 signing key. Public — no credential needed. */
  async pubkey() {
    return this.#request("GET", "/chain/pubkey", { auth: false });
  }

  /** Service status, and whether the chain database is bound. */
  async health() {
    return this.#request("GET", "/health", { auth: false });
  }
}

/**
 * Submit one proposal and decide whether execution may proceed.
 * Resolves to the Verdict when it may — or null in shadow mode when the
 * gate could not be reached. In enforce mode, throws GateVeto,
 * GateEscalation, or VerityError when it may not. Internal to `guard`,
 * exported for runtimes that manage their own call sites.
 */
export async function check(client, proposal, { mode = "shadow", onEscalate } = {}) {
  if (mode !== "shadow" && mode !== "enforce") {
    throw new Error(`verity: mode must be "shadow" or "enforce", got ${JSON.stringify(mode)}`);
  }
  let v;
  try {
    v = await client.verdict(proposal);
  } catch (err) {
    if (mode === "enforce") throw err; // fail closed: no verdict, no execution
    console.warn("verity: gate unreachable in shadow mode; proceeding without a verdict");
    return null; // fail open: the watch never breaks the work
  }
  if (mode === "shadow") return v;
  if (v.allowed) return v;
  if (v.vetoed) throw new GateVeto(v);
  if (v.escalated) {
    if (onEscalate && (await onEscalate(v))) return v;
    throw new GateEscalation(v);
  }
  throw new VerityError(`unrecognized verdict from the gate: ${JSON.stringify(v.verdict)}`, { body: v.raw });
}

/**
 * Gate a function call: submit the proposal before `fn` runs.
 *
 * mode "shadow" (default): `fn` always runs; resolves to [result, verdict].
 * mode "enforce": `fn` runs only on ALLOW; resolves to the result alone.
 * VETO throws GateVeto; ESCALATE throws GateEscalation unless `onEscalate`
 * is given and returns true. A gate failure fails closed in enforce mode
 * and fails open (with a warning, verdict null) in shadow mode.
 */
export async function guard(client, proposal, fn, { mode = "shadow", onEscalate } = {}) {
  const verdict = await check(client, proposal, { mode, onEscalate });
  const result = await fn();
  return mode === "shadow" ? [result, verdict] : result;
}
