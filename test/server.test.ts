/**
 * End-to-end server tests over real HTTP (ephemeral port, fake verdict RPC).
 * Simulates the actual x402 client flow exactly as an agent would:
 *   1. GET /verify without payment -> 402 challenge
 *   2. build EIP-3009 authorization from the challenge's accepts[0]
 *   3. sign with a THROWAWAY dev key (generated here, never persisted,
 *      zero funds — nothing to do with the operation's wallet)
 *   4. retry with X-PAYMENT -> 200 verdict + X-PAYMENT-RESPONSE header
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { encodeAbiParameters, toHex } from "viem";
import { createApp } from "../src/server.js";
import { TRANSFER_TOPIC, type VerdictClient } from "../src/verdict.js";
import { DEFAULT_PAY_TO, DEFAULT_PRICE_ATOMIC, USDC, type EndpointConfig } from "../src/config.js";
import { buildTypedData } from "../src/x402.js";

const cfg: EndpointConfig = {
  port: 0,
  baseUrl: "https://proto.example",
  rpcUrls: [],
  priceAtomic: DEFAULT_PRICE_ATOMIC,
  payTo: DEFAULT_PAY_TO as `0x${string}`,
  maxTimeoutSeconds: 30,
};

const PAYER_ADDR = "0x1111111111111111111111111111111111111111";
const SHOP = "0x2222222222222222222222222222222222222222";
const TXHASH = ("0x" + "cd".repeat(32)) as `0x${string}`;

function fakeVerdictClient(): VerdictClient {
  const padAddr = (a: string) => encodeAbiParameters([{ type: "address" }], [a as `0x${string}`]);
  return {
    async getChainId() {
      return 8453;
    },
    async getTransactionReceipt() {
      return {
        status: "success" as const,
        blockNumber: 30_000n,
        from: PAYER_ADDR,
        logs: [
          {
            address: USDC,
            topics: [TRANSFER_TOPIC as `0x${string}`, padAddr(PAYER_ADDR), padAddr(SHOP)],
            data: encodeAbiParameters([{ type: "uint256" }], [DEFAULT_PRICE_ATOMIC]),
          },
        ],
      };
    },
    async getTransaction() {
      return null;
    },
  };
}

let server: ReturnType<typeof createApp>;
let baseUrl = "";

before(async () => {
  server = createApp({ config: cfg, clients: [fakeVerdictClient()], log: () => {} });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no port");
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(() => new Promise<void>((resolve) => server.close(() => resolve())));

const QUERY = `/verify?tx=${TXHASH}&to=${SHOP}&min=0.01&token=usdc`;

test("unpaid request -> 402 with a spec-shaped x402 challenge", async () => {
  const res = await fetch(`${baseUrl}${QUERY}`);
  assert.equal(res.status, 402);
  const body = (await res.json()) as { x402Version: number; error: string; accepts: Array<Record<string, unknown>> };
  assert.equal(body.x402Version, 1);
  assert.match(body.error, /X-PAYMENT/);
  const a = body.accepts[0]!;
  assert.equal(a.scheme, "exact");
  assert.equal(a.network, "base");
  assert.equal(a.maxAmountRequired, "10000");
  assert.equal(a.asset, USDC);
  assert.equal(a.payTo, DEFAULT_PAY_TO);
  assert.equal(a.maxTimeoutSeconds, 30);
  assert.deepEqual(a.extra, { name: "USD Coin", version: "2" });
  assert.equal(a.resource, "https://proto.example/verify");
});

test("bad query params are rejected for free (400, no payment demanded)", async () => {
  const res = await fetch(`${baseUrl}/verify?tx=nope`);
  assert.equal(res.status, 400);
  const body = (await res.json()) as { error?: string };
  assert.match(body.error ?? "", /tx/);
});

test("garbage X-PAYMENT -> 400 malformed", async () => {
  const res = await fetch(`${baseUrl}${QUERY}`, { headers: { "X-PAYMENT": "%%%not-json%%%" } });
  assert.equal(res.status, 400);
});

test("full x402 flow: 402 -> sign per challenge -> 200 verdict + settlement header", async () => {
  // step 1: get the challenge
  const first = await fetch(`${baseUrl}${QUERY}`);
  assert.equal(first.status, 402);
  const challenge = (await first.json()) as { accepts: Array<Record<string, string> & { maxAmountRequired: string; payTo: string; maxTimeoutSeconds: number }> };
  const req = challenge.accepts[0]!;

  // step 2+3: build + sign the EIP-3009 authorization (throwaway dev key)
  const throwaway = privateKeyToAccount(generatePrivateKey());
  const nowSec = Math.floor(Date.now() / 1000);
  const authorization = {
    from: throwaway.address,
    to: req.payTo,
    value: req.maxAmountRequired,
    validAfter: String(nowSec - 60),
    validBefore: String(nowSec + req.maxTimeoutSeconds),
    nonce: toHex(Math.floor(Math.random() * 2 ** 48), { size: 32 }),
  };
  const signature = await throwaway.signTypedData(buildTypedData(authorization));

  // step 4: retry with X-PAYMENT (standard base64, as the official client encodes)
  const header = Buffer.from(
    JSON.stringify({ x402Version: 1, scheme: "exact", network: "base", payload: { signature, authorization } }),
    "utf-8"
  ).toString("base64");
  const res = await fetch(`${baseUrl}${QUERY}`, { headers: { "X-PAYMENT": header } });

  assert.equal(res.status, 200);
  const settlementRaw = res.headers.get("x-payment-response");
  assert.ok(settlementRaw, "X-PAYMENT-RESPONSE header present");
  const settlement = JSON.parse(Buffer.from(settlementRaw!, "base64").toString("utf-8")) as {
    success: boolean;
    transaction: string;
    network: string;
    payer: string;
  };
  assert.equal(settlement.success, true);
  assert.equal(settlement.network, "base");
  assert.equal(settlement.payer, throwaway.address);
  assert.equal(settlement.transaction, ""); // prototype verifies but does not settle

  const verdict = (await res.json()) as Record<string, unknown>;
  assert.equal(verdict.paid, true);
  assert.equal(verdict.amount, "0.01");
  assert.equal(verdict.txHash, TXHASH);
  assert.equal(verdict.token, "usdc");
  assert.equal(verdict.chain, "base");
  assert.ok(typeof verdict.block === "number");
  assert.ok(typeof verdict.verifiedAt === "string");
});

test("the same X-PAYMENT cannot be replayed for a second verdict", async () => {
  const throwaway = privateKeyToAccount(generatePrivateKey());
  const nowSec = Math.floor(Date.now() / 1000);
  const authorization = {
    from: throwaway.address,
    to: DEFAULT_PAY_TO,
    value: "10000",
    validAfter: String(nowSec - 60),
    validBefore: String(nowSec + 300),
    nonce: toHex(Math.floor(Math.random() * 2 ** 48), { size: 32 }),
  };
  const signature = await throwaway.signTypedData(buildTypedData(authorization));
  const header = Buffer.from(
    JSON.stringify({ x402Version: 1, scheme: "exact", network: "base", payload: { signature, authorization } }),
    "utf-8"
  ).toString("base64");

  const first = await fetch(`${baseUrl}${QUERY}`, { headers: { "X-PAYMENT": header } });
  assert.equal(first.status, 200);
  const second = await fetch(`${baseUrl}${QUERY}`, { headers: { "X-PAYMENT": header } });
  assert.equal(second.status, 402);
});

test("free routes: / descriptor and /health", async () => {
  const root = await fetch(`${baseUrl}/`);
  assert.equal(root.status, 200);
  const desc = (await root.json()) as Record<string, unknown>;
  assert.equal(desc.service, "base-payment-verification");
  assert.equal(desc.payTo, DEFAULT_PAY_TO);
  const health = await fetch(`${baseUrl}/health`);
  assert.deepEqual(await health.json(), { ok: true });
});

test("POST /verify with JSON body works behind the same payment gate", async () => {
  const res = await fetch(`${baseUrl}/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tx: TXHASH, to: SHOP, min: "0.01", token: "usdc" }),
  });
  assert.equal(res.status, 402); // payment gate applies to POST too
});
