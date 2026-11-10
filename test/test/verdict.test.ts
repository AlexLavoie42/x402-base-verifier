/**
 * Verdict-service unit tests with fake RPC clients (offline).
 * The fake receipts mirror exactly what viem getTransactionReceipt returns
 * for a USDC Transfer log: topics = [Transfer, from, to], data = value.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeAbiParameters, toHex } from "viem";
import { checkPayment, TRANSFER_TOPIC, type VerdictClient } from "../src/verdict.js";
import { USDC } from "../src/config.js";

const PAYER = "0x1111111111111111111111111111111111111111";
const SHOP = "0x2222222222222222222222222222222222222222";
const OTHER = "0x3333333333333333333333333333333333333333";

function padAddr(a: string): `0x${string}` {
  return encodeAbiParameters([{ type: "address" }], [a as `0x${string}`]);
}
function uint(v: bigint): `0x${string}` {
  return encodeAbiParameters([{ type: "uint256" }], [v]);
}
function usdcLog(from: string, to: string, value: bigint) {
  return { address: USDC, topics: [TRANSFER_TOPIC as `0x${string}`, padAddr(from), padAddr(to)], data: uint(value) };
}

function fakeClient(opts: {
  receipt?: { status: "success"; blockNumber: bigint; logs: Array<{ address: string; topics: `0x${string}`[]; data: `0x${string}` }> } | null;
  tx?: { from: string; to: string | null; value: bigint } | null;
  failFirst?: boolean;
}): VerdictClient {
  return {
    async getChainId() {
      if (opts.failFirst) throw new Error("429 too many requests");
      return 8453;
    },
    async getTransactionReceipt() {
      if (opts.failFirst) throw new Error("429 too many requests");
      if (opts.receipt === null || opts.receipt === undefined) return null;
      return { status: "success" as const, blockNumber: opts.receipt.blockNumber, from: PAYER, logs: opts.receipt.logs };
    },
    async getTransaction() {
      return opts.tx ?? null;
    },
  };
}

const TXHASH = ("0x" + "ab".repeat(32)) as `0x${string}`;

test("USDC: sums matching transfer logs and reports paid over the threshold", async () => {
  const client = fakeClient({
    receipt: {
      status: "success",
      blockNumber: 12_345n,
      logs: [
        usdcLog(PAYER, OTHER, 900n), // not our recipient
        usdcLog(PAYER, SHOP, 1_000_000n), // 1.00 USDC
        usdcLog(OTHER, SHOP, 500_000n), // 0.50 USDC
      ],
    },
  });
  const v = await checkPayment([client], { txHash: TXHASH, to: SHOP, minAtomic: 1_000_000n, token: "usdc" });
  assert.equal(v.paid, true);
  assert.equal(v.amount, "1.5");
  assert.equal(v.block, 12345);
  assert.equal(v.from, PAYER); // first matching log's sender
  assert.equal(v.token, "usdc");
  assert.equal(v.matched, 2);
  assert.equal(v.found, true);
  assert.equal(v.chain, "base");
  assert.ok(new Date(v.verifiedAt).getTime() > 0);
});

test("USDC: below threshold is not paid even though a transfer exists", async () => {
  const client = fakeClient({
    receipt: { status: "success", blockNumber: 1n, logs: [usdcLog(PAYER, SHOP, 9_999n)] }, // 0.009999 USDC
  });
  const v = await checkPayment([client], { txHash: TXHASH, to: SHOP, minAtomic: 10_000n, token: "usdc" });
  assert.equal(v.paid, false);
  assert.equal(v.amount, "0.009999");
  assert.equal(v.matched, 1);
});

test("USDC: transfers of other tokens are ignored", async () => {
  const client = fakeClient({
    receipt: {
      status: "success",
      blockNumber: 1n,
      logs: [{ address: OTHER, topics: [TRANSFER_TOPIC as `0x${string}`, padAddr(PAYER), padAddr(SHOP)], data: uint(10n ** 18n) }],
    },
  });
  const v = await checkPayment([client], { txHash: TXHASH, to: SHOP, minAtomic: 1n, token: "usdc" });
  assert.equal(v.paid, false);
  assert.equal(v.matched, 0);
  assert.equal(v.amount, "0");
});

test("unknown transaction returns a structured not-found verdict", async () => {
  const v = await checkPayment([fakeClient({})], { txHash: TXHASH, minAtomic: 1n, token: "usdc" });
  assert.equal(v.found, false);
  assert.equal(v.paid, false);
  assert.match(v.reason ?? "", /not found/);
});

test("ETH: direct transfer value with status success", async () => {
  const client = fakeClient({
    receipt: { status: "success", blockNumber: 9n, logs: [] },
    tx: { from: PAYER, to: SHOP, value: 10n ** 15n },
  });
  const ok = await checkPayment([client], { txHash: TXHASH, to: SHOP, minAtomic: 5n * 10n ** 14n, token: "eth" });
  assert.equal(ok.paid, true);
  assert.equal(ok.amount, "0.001");
  const short = await checkPayment([client], { txHash: TXHASH, to: SHOP, minAtomic: 2n * 10n ** 15n, token: "eth" });
  assert.equal(short.paid, false);
});

test("RPC fallback: first client failing is transparent", async () => {
  const dead = fakeClient({ failFirst: true });
  const alive = fakeClient({
    receipt: { status: "success", blockNumber: 7n, logs: [usdcLog(PAYER, SHOP, 10_000n)] },
  });
  const v = await checkPayment([dead, alive], { txHash: TXHASH, to: SHOP, minAtomic: 10_000n, token: "usdc" });
  assert.equal(v.paid, true);
  assert.equal(v.block, 7);
});

test("all RPCs down raises so the server can 502 honestly", async () => {
  await assert.rejects(
    checkPayment([fakeClient({ failFirst: true })], { txHash: TXHASH, minAtomic: 1n, token: "usdc" }),
    /all RPCs failed/
  );
});
