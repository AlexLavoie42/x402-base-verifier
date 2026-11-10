/**
 * End-to-end server tests over real HTTP (ephemeral port, fake verdict RPC,
 * LOCAL facilitator — no network). Simulates the official x402 v2 client flow:
 *   1. GET /verify without payment -> 402 with the PaymentRequired challenge
 *      in the PAYMENT-REQUIRED response header (x402Version 2)
 *   2. build an EIP-3009 authorization from the challenge's accepts[0]
 *   3. sign with a THROWAWAY dev key (generated here, never persisted,
 *      zero funds — nothing to do with the operation's wallet)
 *   4. retry with PAYMENT-SIGNATURE -> 200 verdict + PAYMENT-RESPONSE header
 *
 * The facilitator verification is mocked via src/local-facilitator.ts (same
 * trick as the old payment-path tests: it really recovers the EIP-712
 * signature locally, but settles nothing and touches no network).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { encodeAbiParameters, toHex } from "viem";
import { createApp } from "../src/server.js";
import { createLocalFacilitator } from "../src/local-facilitator.js";
import { TRANSFER_TOPIC, type VerdictClient } from "../src/verdict.js";
import { CHAIN_ID, DEFAULT_PAY_TO, DEFAULT_PRICE_ATOMIC, DEFAULT_SCAN_PRICE_ATOMIC, USDC, type EndpointConfig } from "../src/config.js";
import { TRANSFER_WITH_AUTHORIZATION_TYPES } from "../src/x402.js";

const cfg: EndpointConfig = {
  port: 0,
  baseUrl: "https://proto.example",
  rpcUrls: [],
  priceAtomic: DEFAULT_PRICE_ATOMIC,
  scanPriceAtomic: DEFAULT_SCAN_PRICE_ATOMIC,
  payTo: DEFAULT_PAY_TO as `0x${string}`,
  maxTimeoutSeconds: 30,
  facilitatorUrl: "http://facilitator.invalid", // never contacted: local facilitator injected
};

const PAYER_ADDR = "0x1111111111111111111111111111111111111111";
const SHOP = "0x2222222222222222222222222222222222222222";
const TXHASH = ("0x" + "cd".repeat(32)) as `0x${string}`;

function fakeVerdictClient(): VerdictClient {
  const padAddr = (a: string) => encodeAbiParameters([{ type: "address" }], [a as `0x${string}`]);
  return {
    async getChainId() {
      return CHAIN_ID;
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

let server: Server;
let baseUrl = "";

before(async () => {
  const app = createApp({
    config: cfg,
    clients: [fakeVerdictClient()],
    facilitator: createLocalFacilitator(),
    log: () => {},
  });
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no port");
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(() => new Promise<void>((resolve) => server.close(() => resolve())));

const QUERY = `/verify?tx=${TXHASH}&to=${SHOP}&min=0.01&token=usdc`;

/** Decode the v2 402 challenge from the PAYMENT-REQUIRED header. */
interface PaymentRequiredHeader {
  x402Version: number;
  error?: string;
  resource: Record<string, unknown>;
  accepts: Array<{
    scheme: string;
    network: string;
    asset: string;
    amount: string;
    payTo: string;
    maxTimeoutSeconds: number;
    extra: Record<string, unknown>;
  }>;
  extensions?: Record<string, unknown>;
}

async function getChallenge(url: string): Promise<{ status: number; header: PaymentRequiredHeader; raw: string }> {
  const res = await fetch(url);
  assert.equal(res.status, 402);
  const raw = res.headers.get("payment-required");
  assert.ok(raw, "PAYMENT-REQUIRED header present");
  const header = JSON.parse(Buffer.from(raw!, "base64").toString("utf-8")) as PaymentRequiredHeader;
  return { status: res.status, header, raw: raw! };
}

/** Build + sign a v2 payment for the given challenge (throwaway dev key). */
async function signPayment(
  header: PaymentRequiredHeader,
  overrides: { value?: string; to?: string; expired?: boolean } = {},
): Promise<string> {
  const req = header.accepts[0]!;
  const throwaway = privateKeyToAccount(generatePrivateKey());
  const nowSec = Math.floor(Date.now() / 1000);
  const authorization = {
    from: throwaway.address,
    to: (overrides.to ?? req.payTo) as `0x${string}`,
    value: overrides.value ?? req.amount,
    validAfter: "0",
    validBefore: String(nowSec + (overrides.expired ? -1 : req.maxTimeoutSeconds)),
    nonce: toHex(Math.floor(Math.random() * 2 ** 48), { size: 32 }),
  };
  const signature = await throwaway.signTypedData({
    domain: {
      name: req.extra.name as string,
      version: req.extra.version as string,
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
  // The v2 wire shape the official client emits (x402Client.createPaymentPayload)
  return Buffer.from(
    JSON.stringify({
      x402Version: 2,
      resource: header.resource,
      accepted: req,
      payload: { signature, authorization },
    }),
    "utf-8",
  ).toString("base64");
}

test("unpaid request -> 402 with the v2 PaymentRequired challenge in the PAYMENT-REQUIRED header", async () => {
  const { header } = await getChallenge(`${baseUrl}${QUERY}`);
  assert.equal(header.x402Version, 2);
  assert.equal(header.error, "Payment required");
  const a = header.accepts[0]!;
  assert.equal(a.scheme, "exact");
  assert.equal(a.network, "eip155:8453");
  assert.equal(a.amount, "10000"); // 10000 atomic USDC = $0.01
  assert.equal(a.asset, USDC);
  assert.equal(a.payTo, DEFAULT_PAY_TO);
  assert.equal(a.maxTimeoutSeconds, 30);
  assert.deepEqual(a.extra, { name: "USD Coin", version: "2" });
  assert.equal((header.resource as { url: string }).url, "https://proto.example/verify");
  // bazaar discovery declaration rides along in the challenge extensions
  const bazaar = header.extensions?.bazaar as { info?: unknown; schema?: unknown } | undefined;
  assert.ok(bazaar, "bazaar extension declared");
  assert.ok(bazaar.info && bazaar.schema);
});

test("the 402 body stays JSON and CORS headers are kept", async () => {
  const res = await fetch(`${baseUrl}${QUERY}`);
  assert.equal(res.status, 402);
  assert.equal(res.headers.get("access-control-allow-origin"), "*");
  const body = (await res.json()) as { error?: string };
  assert.equal(body.error, "Payment required");
});

test("bad query params are rejected for free (400, no payment demanded)", async () => {
  const res = await fetch(`${baseUrl}/verify?tx=nope`);
  assert.equal(res.status, 400);
  const body = (await res.json()) as { error?: string };
  assert.match(body.error ?? "", /tx/);
});

test("garbage PAYMENT-SIGNATURE header -> 402 challenge again (SDK semantics)", async () => {
  const res = await fetch(`${baseUrl}${QUERY}`, { headers: { "PAYMENT-SIGNATURE": "%%%not-base64%%%" } });
  assert.equal(res.status, 402);
  assert.ok(res.headers.get("payment-required"));
});

test("full x402 v2 flow: 402 -> sign per challenge -> 200 verdict + PAYMENT-RESPONSE header", async () => {
  const { header } = await getChallenge(`${baseUrl}${QUERY}`);
  const payment = await signPayment(header);

  const res = await fetch(`${baseUrl}${QUERY}`, { headers: { "PAYMENT-SIGNATURE": payment } });
  assert.equal(res.status, 200);

  const receiptRaw = res.headers.get("payment-response");
  assert.ok(receiptRaw, "PAYMENT-RESPONSE header present");
  const receipt = JSON.parse(Buffer.from(receiptRaw!, "base64").toString("utf-8")) as {
    success: boolean;
    transaction: string;
    network: string;
    payer?: string;
  };
  assert.equal(receipt.success, true);
  assert.equal(receipt.network, "eip155:8453");
  assert.equal(receipt.transaction, ""); // verified but NOT settled on-chain — receive-only (as in v1)

  const verdict = (await res.json()) as Record<string, unknown>;
  assert.equal(verdict.paid, true);
  assert.equal(verdict.amount, "0.01");
  assert.equal(verdict.txHash, TXHASH);
  assert.equal(verdict.token, "usdc");
  assert.equal(verdict.chain, "base");
  assert.ok(typeof verdict.block === "number");
  assert.ok(typeof verdict.verifiedAt === "string");
});

test("the same payment cannot be replayed for a second verdict (facilitator nonce guard)", async () => {
  const { header } = await getChallenge(`${baseUrl}${QUERY}`);
  const payment = await signPayment(header);

  const first = await fetch(`${baseUrl}${QUERY}`, { headers: { "PAYMENT-SIGNATURE": payment } });
  assert.equal(first.status, 200);
  const second = await fetch(`${baseUrl}${QUERY}`, { headers: { "PAYMENT-SIGNATURE": payment } });
  assert.equal(second.status, 402);
  const retry = JSON.parse(Buffer.from(second.headers.get("payment-required") ?? "", "base64").toString("utf-8")) as {
    error?: string;
  };
  assert.match(retry.error ?? "", /nonce already used/);
});

test("a payment that fails facilitator verification gets a 402 with the invalid reason", async () => {
  const { header } = await getChallenge(`${baseUrl}${QUERY}`);
  // sign for a different amount than accepted -> verify fails locally in the fake facilitator
  const payment = await signPayment(header, { value: "1" });
  const res = await fetch(`${baseUrl}${QUERY}`, { headers: { "PAYMENT-SIGNATURE": payment } });
  assert.equal(res.status, 402);
  const challenge = JSON.parse(Buffer.from(res.headers.get("payment-required") ?? "", "base64").toString("utf-8")) as {
    error?: string;
  };
  assert.match(challenge.error ?? "", /amount|requirements/i);
});

test("expired authorization is rejected by the (local) facilitator verification", async () => {
  const { header } = await getChallenge(`${baseUrl}${QUERY}`);
  const payment = await signPayment(header, { expired: true });
  const res = await fetch(`${baseUrl}${QUERY}`, { headers: { "PAYMENT-SIGNATURE": payment } });
  assert.equal(res.status, 402);
});

test("free routes: / descriptor and /health", async () => {
  const root = await fetch(`${baseUrl}/`);
  assert.equal(root.status, 200);
  const desc = (await root.json()) as Record<string, unknown>;
  assert.equal(desc.service, "base-payment-verification");
  assert.equal(desc.payTo, DEFAULT_PAY_TO);
  assert.equal(desc.x402Version, 2);
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
  assert.ok(res.headers.get("payment-required"));
});

test("POST /verify with a non-JSON body -> 400", async () => {
  const res = await fetch(`${baseUrl}/verify`, {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: "not json {",
  });
  assert.equal(res.status, 400);
  const body = (await res.json()) as { error?: string };
  assert.match(body.error ?? "", /JSON|json/);
});

test("bare GET without params -> 402 challenge (Bazaar/validator preflight), not a 400", async () => {
  const { header } = await getChallenge(`${baseUrl}/verify`);
  assert.ok(Array.isArray(header.accepts) && header.accepts.length > 0);
});

test("invalid params WITH arguments still fail free with 400", async () => {
  const res = await fetch(`${baseUrl}/verify?tx=notahash&to=0x123`);
  assert.equal(res.status, 400);
});

test("unknown route -> JSON 404", async () => {
  const res = await fetch(`${baseUrl}/nope`);
  assert.equal(res.status, 404);
  const body = (await res.json()) as { error?: string };
  assert.equal(body.error, "not found");
});
