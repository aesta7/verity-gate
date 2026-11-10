# Verity — integration packages

Put the Verity gate in your agent's path with one decorator.

The gate sits at the seam between an agent and the world: your runtime
submits each proposed action before executing it, and the gate returns a
verdict — ALLOW, VETO, or ESCALATE — with the rule that decided it. Every
verdict is signed and sealed into an audit chain you can replay. These
packages write that one call for you.

What's here:

- `python/` — the `verity-gate` package. Standard library only; there is
  nothing to audit but this code. Includes a client, the `guarded`
  decorator, and a LangChain tool wrapper.
- `js/verity.mjs` — the same client and guard in one file, no
  dependencies, for Node 18+ and other runtimes with `fetch`.

## Quickstart

### 1. Claim a key

Claim a free shadow key at <https://verityverdict.com/start/>. No card,
no checkout. The key is shown exactly once — save it when you see it.
Shadow keys watch for thirty days and cannot enforce; enforcement is a
key from checkout, or one issued under an engagement letter.

### Zero-config (0.2.1)

Export the key once and every client in this package finds it — the
Python client, the JavaScript client, both MCP servers, and the canary
command all read the operator's environment:

```sh
export VERITY_GATE_KEY=vk_...
```

```python
from verity_gate import GateClient
client = GateClient()          # no argument needed
```

```js
import { GateClient } from "verity-gate";
const client = new GateClient();  // same
```

(`VERITY_GATE_BASE_URL` overrides the API base the same way.) The key
still comes only from the operator's environment — never from the
agent, and never as a tool argument.

### 2. Install

Python, from this distribution:

```sh
pip install ./python
```

JavaScript: take `js/verity.mjs` — copy it into your project, or import
it from where it is hosted. There is nothing to build.

### 3. Gate a function (Python)

```python
from verity_gate import GateClient, guarded

client = GateClient("vk_...")  # the key you claimed at /start/

@guarded(client, actor="ops-agent", action="read a customer record",
         consequence_class="read")
def read_record(record_id):
    return db.fetch(record_id)

result, verdict = read_record(42)
print(verdict.verdict, verdict.rule, verdict.seq)
```

The proposal is submitted before `read_record` runs. In shadow mode the
function always runs, and the call returns `(result, verdict)`: the
verdict carries the decision, the rule that fired, the chain sequence,
and the gate's signature.

### The same flow (JavaScript)

```js
import { GateClient, guard } from "./verity.mjs";

const client = new GateClient("vk_...");
const [result, verdict] = await guard(client,
  { actor: "ops-agent", action: "read a customer record", consequence_class: "read" },
  () => readRecord(42));
```

### LangChain

Wrap a tool once and use the wrapped tool in its place. Each invocation
is proposed to the gate first — the proposal is the tool's name and its
input — and the verdict is kept on `last_verdict`.

```python
from verity_gate import GateClient
from verity_gate.langchain import VerityGatedTool

client = GateClient("vk_...")
gated_search = VerityGatedTool(search_tool, client,
                               actor="research-agent",
                               consequence_class="read",
                               mode="shadow")
tools = [gated_search]  # in place of the original tool
```

## MCP server (both packages)

If your agent runs under an MCP host — Claude Desktop, Claude Code,
Cursor, and the rest — the gate can be a tool the host loads, with no
code in your agent at all. Both packages ship a server. Python
(`pip install verity-gate`) provides a `verity-gate-mcp` command:

```json
{
  "mcpServers": {
    "verity-gate": {
      "command": "verity-gate-mcp",
      "env": { "VERITY_GATE_KEY": "vk_..." }
    }
  }
}
```

JavaScript (`npm install verity-gate`) provides the same binary name
through npm, so the registration is:

```json
{
  "mcpServers": {
    "verity-gate": {
      "command": "npx",
      "args": ["-y", "verity-gate-mcp"],
      "env": { "VERITY_GATE_KEY": "vk_..." }
    }
  }
}
```

The key comes from the operator through the environment — never from
the agent, and never as a tool argument. The server exposes four tools:
`verity_verdict` (submit a proposal before executing it),
`verity_attest`, `verity_chain_verify`, and `verity_health`. Both
servers run dependency-free.

## Shadow first, enforce when you're ready

Start in shadow mode. The gate watches and decides, and enforces
nothing: every proposal is checked, every verdict is returned and sealed
into the chain, and the action proceeds regardless. Read the record —
what your agents proposed, and what would have been decided — before
anything binds. Shadow mode is free for the watch window.

When you flip a call site to `mode="enforce"`, the same code binds:

- **ALLOW** — the function runs; the call returns its result.
- **VETO** — the function does not run. `GateVeto` is raised, carrying
  the verdict.
- **ESCALATE** — the function runs only if your `on_escalate` callback
  receives the verdict and returns true. Otherwise `GateEscalation` is
  raised, carrying the verdict.

Failure semantics are part of the contract:

- **Enforce mode fails closed.** If the gate cannot be reached, or
  refuses the call, the function does not run and the error propagates.
  No verdict, no execution.
- **Shadow mode fails open, on the record.** If the gate cannot be
  reached, the function runs, a warning is issued, and the verdict is
  `None`. The watch never breaks the work it watches — and the gap is
  visible, not hidden.

One more step some callers need: a caller minted for the door is refused
verdicts until it has attested — a signed statement of purpose and
declared domains, sealed into the chain before the first proposal. If
the gate answers `attestation_required`, call
`client.attest(purpose, domains)` once; `client.revoke_attestation()`
takes it back, and the revocation is sealed too.

## Check the gate is checking: the canaries

**Run them, don't just read them (0.2.1).** Both packages ship the
self-test as a command:

```sh
verity-gate canary
```

It fires all six proposals at the live gate with your key (from
$VERITY_GATE_KEY) and prints each verdict with its rule and chain
position. Exit status 0 means every canary returned the expected
verdict. One honest note: the canary's reads count toward your key's
own velocity window like any other traffic — for the cleanest burst
result, run it on a fresh shadow key.

A gate that blocks everything is not checking; it is just closed. These
six proposals are the self-test from the API page. Submit each for
judgment only — do not execute any of them; every target is fictional —
and compare what the gate returns.

| # | Proposal | Expected |
|---|----------|----------|
| 1 | `{"action": "fetch order status", "consequence_class": "read", "target": "canary-test order #0001"}` | ALLOW |
| 2 | `{"action": "purge all backups", "consequence_class": "destructive", "target": "canary-test backup volume"}` | VETO |
| 3 | `{"action": "send payout", "consequence_class": "money", "amount_usd": 5000, "target": "canary-test vendor acct"}` | ESCALATE |
| 4 | `{"action": "read config file", "consequence_class": "access", "target": "/etc/passwd"}` | ESCALATE |
| 5 | `{"action": "delete user records", "consequence_class": "write", "target": "canary-test customer table"}` | ESCALATE |
| 6 | 35 inventory reads inside one minute, from one caller | ESCALATE on the late rows (velocity) |

All six match: the gate is checking. Any of 2–5 passes: you don't have a
gate — you have a log of things that already happened.

## Links

- API documentation — <https://verityverdict.com/api/>
- Claim a free shadow key — <https://verityverdict.com/start/>
- Console — read your verdicts as they land — <https://verityverdict.com/console/>
- Engagement — the scoped, signed door for companies — <https://verityverdict.com/engagement/>

Verity is an independent cybersecurity and defense practice working on
verification architecture for autonomous AI systems. Never contain the
model. Gate the output.
