/**
 * Live smoke test (read-only): proves the x402 v2 loop end to end against
 * real Base data without spending anything.
 *
 *   1. start the app with real public-RPC verdict clients and the LOCAL
 *      facilitator (offline; the production server instead uses Coinbase's
 *      hosted facilitator, which would reject a throwaway key's zero balance)
 *   2. find a recent real USDC transfer on Base (read-only getLogs)
 *   3. GET /verify unpaid          -> expect 402 + PAYMENT-REQUIRED header
 *      (base64 PaymentRequired, x402Version 2)
 *   4. GET /verify with PAYMENT-SIGNATURE -> expect 200 + real verdict
 *      + PAYMENT-RESPONSE header (settlement is the local facilitator's
 *      SYNTHETIC receipt — no transaction is ever created or broadcast)
 *
 * Run: npx tsx scripts/smoke.ts
 */
import { createPublicClient, http } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { toHex } from "viem";
import { CHAIN_ID, DEFAULT_RPC_URLS, USDC, loadConfig } from "../src/config.js";
import { TRANSFER_WITH_AUTHORIZATION_TYPES } from "../src/x402.js";
import { makeRpcClients, TRANSFER_TOPIC } from "../src/verdict.js";
import { createLocalFacilitator } from "../src/local-facilitator.js";
import { createApp } from "../src/server.js";

async function main() {
  const cfg = loadConfig({ PORT: "3999", BASE_URL: "http://localhost:3999" }); // app.listen(0) overrides the port
  const app = createApp({
    config: cfg,
    clients: makeRpcClients(DEFAULT_RPC_URLS),
    facilitator: createLocalFacilitator(), // offline stand-in; see header comment
    log: (m) => console.log("  [server]", m),
  });
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", r));
  const addr = server.address();
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
  console.log(`demo tx: ${demo.transactionHash} (USDC -> ${demoTo})`);

  const query = `/verify?tx=${demo.transactionHash}&to=${demoTo}&min=0.000001&token=usdc`;

  // 1) unpaid -> 402 + PAYMENT-REQUIRED header
  const unpaid = await fetch(`${base}${query}`);
  const challenge = JSON.parse(
    Buffer.from(unpaid.headers.get("payment-required") ?? "", "base64").toString("utf-8"),
  ) as {
    x402Version: number;
    resource: unknown;
    accepts: Array<{
      scheme: string;
      network: string;
      asset: string;
      amount: string;
      payTo: string;
      maxTimeoutSeconds: number;
      extra: { name?: string; version?: string };
    }>;
  };
  console.log(`\n1) unpaid  -> HTTP ${unpaid.status} ${unpaid.status === 402 ? "(challenge)" : "(UNEXPECTED)"}`);
  console.log("   PAYMENT-REQUIRED accepts[0]:", JSON.stringify(challenge.accepts?.[0]));
  if (unpaid.status !== 402 || challenge.x402Version !== 2) throw new Error("expected a v2 402 challenge");

  // 2) paid with a throwaway dev key -> 200 + verdict + PAYMENT-RESPONSE
  const throwaway = privateKeyToAccount(generatePrivateKey());
  const req = challenge.accepts[0]!;
  const nowSec = Math.floor(Date.now() / 1000);
  const authorization = {
    from: throwaway.address,
    to: req.payTo as `0x${string}`,
    value: req.amount,
    validAfter: "0",
    validBefore: String(nowSec + req.maxTimeoutSeconds),
    nonce: toHex(Math.floor(Math.random() * 2 ** 48), { size: 32 }),
  };
  const signature = await throwaway.signTypedData({
    domain: {
      name: req.extra.name!,
      version: req.extra.version!,
      chainId: CHAIN_ID,
      verifyingContract: req.asset as `0x${string}`,
    },
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      from: authorization.from,
      to: authorization.to,
      value: BigInt(authorization.value),
      validAfter: BigInt(authorization.validAfter),
      validBefore: BigInt(authorization.validBefore),
      nonce: authorization.nonce,
    },
  });
  const paymentHeader = Buffer.from(
    JSON.stringify({
      x402Version: 2,
      resource: challenge.resource,
      accepted: req,
      payload: { signature, authorization },
    }),
    "utf-8",
  ).toString("base64");

  const paid = await fetch(`${base}${query}`, { headers: { "PAYMENT-SIGNATURE": paymentHeader } });
  const verdict = await paid.json();
  const receipt = JSON.parse(Buffer.from(paid.headers.get("payment-response") ?? "", "base64").toString("utf-8"));
  console.log(`\n2) paid    -> HTTP ${paid.status} ${paid.status === 200 ? "(served)" : "(UNEXPECTED)"}`);
  console.log("   verdict   :", JSON.stringify(verdict));
  console.log("   PAYMENT-RESPONSE:", JSON.stringify(receipt), "(local facilitator — synthetic, nothing broadcast)");
  if (paid.status !== 200) throw new Error("expected 200");
  console.log("\nSMOKE OK — v2 402 (PAYMENT-REQUIRED header) -> sign -> 200 loop works against live Base data.");

  server.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
