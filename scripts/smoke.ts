/**
 * Live smoke test (read-only): proves the full x402 loop against real Base
 * data without spending anything — the "payment" is signed by a throwaway
 * dev key holding no funds; the prototype only VERIFIES the signature
 * (local and free) and serves the verdict. No transaction is ever created.
 *
 * Steps:
 *   1. start the app with real public-RPC verdict clients
 *   2. find a recent real USDC transfer on Base (read-only getLogs)
 *   3. GET /verify unpaid         -> expect 402 challenge
 *   4. GET /verify with X-PAYMENT -> expect 200 + real verdict
 *                                    + X-PAYMENT-RESPONSE header
 *
 * Run: npx tsx scripts/smoke.ts
 */
import { createPublicClient, http } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { DEFAULT_RPC_URLS, USDC } from "../src/config.js";
import { buildTypedData } from "../src/x402.js";
import { makeRpcClients, TRANSFER_TOPIC } from "../src/verdict.js";
import { loadConfig } from "../src/config.js";
import { createApp } from "../src/server.js";

async function main() {
  const cfg = loadConfig({ PORT: "3999", BASE_URL: "http://localhost:3999" }); // app.listen(0) overrides the port
  const app = createApp({
    config: cfg,
    clients: makeRpcClients(DEFAULT_RPC_URLS),
    log: (m) => console.log("  [server]", m),
  });
  await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
  const addr = app.address();
  if (addr === null || typeof addr === "string") throw new Error("no port");
  const base = `http://127.0.0.1:${addr.port}`;

  // find a recent real USDC transfer (read-only)
  const publicRpc = createPublicClient({ transport: http(DEFAULT_RPC_URLS[0]!) });
  const latest = await publicRpc.getBlockNumber();
  const logs = await publicRpc.getLogs({
    address: USDC,
    event: {
      type: "event",
      name: "Transfer",
      inputs: [
        { name: "from", type: "address", indexed: true },
        { name: "to", type: "address", indexed: true },
        { name: "value", type: "uint256", indexed: false },
      ],
    },
    fromBlock: latest - 20n,
    toBlock: "latest",
  });
  if (!logs.length) throw new Error("no recent USDC transfers found in the last 20 blocks; rerun");
  const demo = logs[0]!;
  const demoTo = demo.args.to as string;
  const demoValue = demo.args.value as bigint;
  console.log(`demo tx: ${demo.transactionHash} (USDC -> ${demoTo}, ${demoValue} atomic)`);

  const query = `/verify?tx=${demo.transactionHash}&to=${demoTo}&min=0.000001&token=usdc`;

  // 1) unpaid -> 402
  const unpaid = await fetch(`${base}${query}`);
  const challenge = (await unpaid.json()) as { accepts: Array<Record<string, string>> };
  console.log(`\n1) unpaid  -> HTTP ${unpaid.status} ${unpaid.status === 402 ? "(challenge)" : "(UNEXPECTED)"}`);
  console.log("   accepts[0]:", JSON.stringify(challenge.accepts?.[0]));
  if (unpaid.status !== 402) throw new Error("expected 402");

  // 2) paid with a throwaway dev key -> 200 + verdict
  const throwaway = privateKeyToAccount(generatePrivateKey());
  const req = challenge.accepts[0]!;
  const nowSec = Math.floor(Date.now() / 1000);
  const authorization = {
    from: throwaway.address,
    to: req.payTo!,
    value: req.maxAmountRequired!,
    validAfter: String(nowSec - 60),
    validBefore: String(nowSec + Number(req.maxTimeoutSeconds)),
    nonce: "0x" + Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex"),
  };
  const signature = await throwaway.signTypedData(buildTypedData(authorization));
  const header = Buffer.from(
    JSON.stringify({ x402Version: 1, scheme: "exact", network: "base", payload: { signature, authorization } }),
    "utf-8"
  ).toString("base64");

  const paid = await fetch(`${base}${query}`, { headers: { "X-PAYMENT": header } });
  const verdict = await paid.json();
  const settlement = JSON.parse(Buffer.from(paid.headers.get("x-payment-response") ?? "", "base64").toString("utf-8"));
  console.log(`\n2) paid    -> HTTP ${paid.status} ${paid.status === 200 ? "(served)" : "(UNEXPECTED)"}`);
  console.log("   verdict  :", JSON.stringify(verdict));
  console.log("   settlement:", JSON.stringify(settlement));
  if (paid.status !== 200) throw new Error("expected 200");
  console.log("\nSMOKE OK — full 402 -> sign -> 200 loop works against live Base data.");

  app.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
