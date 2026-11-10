#!/usr/bin/env node
/**
 * verity-cli.mjs — command line for verity-gate.
 *
 *   verity-gate canary
 *
 * Runs the six canary checks against the live gate with the caller's own
 * key (from $VERITY_GATE_KEY). Exit status 0 when every canary returns
 * its expected verdict. Mirrors python/verity_gate/cli.py.
 */
import { GateClient, VerityError } from "./verity.mjs";
import { runCanary } from "./canary.mjs";

const NO_KEY =
  "verity-gate: no caller key found. The operator claims a free shadow key\n" +
  "at https://verityverdict.com/start/ and exports it:\n" +
  "    export VERITY_GATE_KEY=vk_...\n" +
  "Agents never provision their own keys.";

async function main(argv) {
  const [command] = argv;
  if (command !== "canary") {
    console.error("usage: verity-gate canary");
    return 2;
  }
  const client = new GateClient();
  if (!client.apiKey) {
    console.error(NO_KEY);
    return 2;
  }
  try {
    const { ok, lines } = await runCanary(client);
    for (const line of lines) console.log(line);
    console.log(ok ? "canary: all checks passed" : "canary: SOME CHECKS FAILED");
    return ok ? 0 : 1;
  } catch (e) {
    if (e instanceof VerityError) {
      console.error(`verity-gate: the gate answered with an error: ${e.message}`);
      return 1;
    }
    throw e;
  }
}

process.exitCode = await main(process.argv.slice(2));
