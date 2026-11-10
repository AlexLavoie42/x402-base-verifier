/**
 * Payment-gate unit tests.
 *
 * The signing key below is a THROWAWAY DEV KEY generated inside the test run
 * (viem generatePrivateKey) and discarded when the process exits. It holds no
 * funds, is never persisted, and has nothing to do with the operation's
 * wallet — the charter's never-touch-real-keys rule is unaffected.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { toHex } from "viem";
import {
  buildChallenge,
  buildRequirements,
  buildTypedData,
  decodePaymentHeader,
  encodeSettlementResponse,
  type Authorization,
  type PaymentPayload,
} from "../src/x402.js";
import { createReplayCache, verifyPayment, stubSettlementCheck } from "../src/payment.js";
import { DEFAULT_PRICE_ATOMIC, DEFAULT_PAY_TO, USDC, type EndpointConfig } from "../src/config.js";

const cfg: EndpointConfig = {
  port: 0,
  baseUrl: "https://proto.example",
  rpcUrls: [],
  priceAtomic: DEFAULT_PRICE_ATOMIC,
  payTo: DEFAULT_PAY_TO as `0x${string}`,
  maxTimeoutSeconds: 30,
  facilitatorUrl: "http://facilitator.invalid", // library tests never contact a facilitator
};
const reqs = buildRequirements(cfg, "https://proto.example/verify");

// Fixed virtual clock so validity windows are deterministic
const NOW = 1_800_000_000;
const now = () => NOW;

const payer = privateKeyToAccount(generatePrivateKey()); // throwaway key, see header comment

function makeAuth(overrides: Partial<Authorization> = {}): Authorization {
  return {
    from: payer.address,
    to: DEFAULT_PAY_TO,
    value: "10000",
    validAfter: String(NOW - 60),
    validBefore: String(NOW + 300),
    nonce: toHex(Math.floor(Math.random() * 2 ** 48), { size: 32 }),
    ...overrides,
  };
}

async function signPayload(auth: Authorization): Promise<PaymentPayload> {
  const signature = await payer.signTypedData(buildTypedData(auth));
  return { x402Version: 1, scheme: "exact", network: "base", payload: { signature, authorization: auth } };
}

function encode(payload: PaymentPayload): string {
  return Buffer.from(JSON.stringify(payload), "utf-8").toString("base64");
}

test("challenge shape matches the x402 v1 spec and the operation's constants", () => {
  const challenge = buildChallenge(cfg, "https://proto.example/verify");
  assert.equal(challenge.x402Version, 1);
  assert.match(challenge.error, /X-PAYMENT/);
  const a = challenge.accepts[0];
  assert.equal(a.scheme, "exact");
  assert.equal(a.network, "base");
  assert.equal(a.maxAmountRequired, "10000");
  assert.equal(a.asset, USDC);
  assert.equal(a.payTo, DEFAULT_PAY_TO);
  assert.equal(a.maxTimeoutSeconds, 30);
  assert.equal(a.mimeType, "application/json");
  assert.deepEqual(a.extra, { name: "USD Coin", version: "2" }); // live-confirmed domain
  assert.equal(a.resource, "https://proto.example/verify");
});

test("a correctly signed EIP-3009 authorization verifies; payer recovered", async () => {
  const header = encode(await signPayload(makeAuth()));
  const v = await verifyPayment(header, reqs, { now });
  assert.equal(v.isValid, true, v.invalidReason);
  assert.equal(v.payer, payer.address);
  assert.equal(v.malformed, false);
  assert.equal(v.onChainCheck?.checked, false); // default stub
});

test("tampered message (value changed after signing) fails signature recovery", async () => {
  const payload = await signPayload(makeAuth());
  payload.payload.authorization = { ...payload.payload.authorization, value: "20000" };
  const v = await verifyPayment(encode(payload), reqs, { now });
  assert.equal(v.isValid, false);
  assert.equal(v.malformed, false);
  assert.match(v.invalidReason ?? "", /signature/);
});

test("payment to the wrong address is rejected before crypto work", async () => {
  const auth = makeAuth({ to: "0x00000000000000000000000000000000000000ff" });
  const v = await verifyPayment(encode(await signPayload(auth)), reqs, { now });
  assert.equal(v.isValid, false);
  assert.match(v.invalidReason ?? "", /payTo/);
});

test("amount below the required price is rejected", async () => {
  const auth = makeAuth({ value: "9999" });
  const v = await verifyPayment(encode(await signPayload(auth)), reqs, { now });
  assert.equal(v.isValid, false);
  assert.match(v.invalidReason ?? "", /below/);
});

test("expired authorization (validBefore <= now) is rejected", async () => {
  const auth = makeAuth({ validBefore: String(NOW) });
  const v = await verifyPayment(encode(await signPayload(auth)), reqs, { now });
  assert.equal(v.isValid, false);
  assert.match(v.invalidReason ?? "", /expired/);
});

test("not-yet-valid authorization is rejected", async () => {
  const auth = makeAuth({ validAfter: String(NOW + 10) });
  const v = await verifyPayment(encode(await signPayload(auth)), reqs, { now });
  assert.equal(v.isValid, false);
  assert.match(v.invalidReason ?? "", /not yet valid/);
});

test("nonce replay against the same endpoint is rejected", async () => {
  const header = encode(await signPayload(makeAuth()));
  const first = await verifyPayment(header, reqs, { now });
  assert.equal(first.isValid, true);
  const second = await verifyPayment(header, reqs, { now });
  assert.equal(second.isValid, false);
  assert.match(second.invalidReason ?? "", /already used/);
});

test("on-chain settled authorization is rejected when the checker reports it", async () => {
  const deps = {
    now,
    settlementCheck: async () => ({ checked: true, settled: true, detail: "authorizationState=true" }),
  };
  const v = await verifyPayment(encode(await signPayload(makeAuth())), reqs, deps);
  assert.equal(v.isValid, false);
  assert.match(v.invalidReason ?? "", /executed on-chain/);
});

test("garbage header is a 400-class malformed error, not a payment failure", async () => {
  const v = await verifyPayment("!!not-base64-json!!", reqs, { now });
  assert.equal(v.isValid, false);
  assert.equal(v.malformed, true);
});

test("header codec: standard base64 and base64url both decode; settlement header round-trips", () => {
  const payload: PaymentPayload = {
    x402Version: 1,
    scheme: "exact",
    network: "base",
    payload: {
      signature: "0x" + "ab".repeat(65),
      authorization: makeAuth(),
    },
  };
  const std = Buffer.from(JSON.stringify(payload), "utf-8").toString("base64");
  const urlSafe = std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  assert.deepEqual(decodePaymentHeader(std), payload);
  assert.deepEqual(decodePaymentHeader(urlSafe), payload);
  const enc = encodeSettlementResponse({ success: true, transaction: "", network: "base", payer: payer.address });
  assert.deepEqual(JSON.parse(Buffer.from(enc, "base64").toString("utf-8")), {
    success: true,
    transaction: "",
    network: "base",
    payer: payer.address,
  });
});

test("replay cache forgets entries once their authorization window expired", () => {
  const cache = createReplayCache(now);
  const auth = makeAuth({ validBefore: String(NOW + 60) });
  assert.equal(cache.seen(auth), false);
  cache.mark(auth);
  assert.equal(cache.seen(auth), true);
  const later = createReplayCache(() => NOW + 61);
  assert.equal(later.seen({ ...auth, nonce: auth.nonce }), false);
});

test("default settlement check is the documented stub", async () => {
  const r = await stubSettlementCheck(makeAuth());
  assert.equal(r.checked, false);
  assert.match(r.detail ?? "", /stub/);
});
