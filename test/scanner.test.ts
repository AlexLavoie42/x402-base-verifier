/**
 * Scanner tests, two layers (all offline):
 *
 *   1. ENGINE — scanSources over the fixture set in test/fixtures/: each
 *      "dirty" fixture triggers its intended rule at the intended line (line
 *      numbers verified against the fixture text itself, not magic numbers),
 *      and the two deliberately careful files (CleanVault/CleanToken) produce
 *      ZERO findings (false-positive control).
 *   2. ROUTE — POST /scan through a real HTTP server with the in-process
 *      facilitator: 402 gate with the $1.00 price + bazaar declaration, free
 *      400 rejections (oversized / malformed), and the full paid flow
 *      (402 -> sign per challenge -> 200 report), mirroring test/server.test.ts.
 *
 * Payment signatures use a THROWAWAY dev key generated per run (zero funds).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Server } from "node:http";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { toHex } from "viem";
import { scanSources, validateScanRequest, type Finding, type ScanReport } from "../src/scanner.js";
import { RULES } from "../src/rules.js";
import { createApp } from "../src/server.js";
import { createLocalFacilitator } from "../src/local-facilitator.js";
import type { VerdictClient } from "../src/verdict.js";
import {
  CHAIN_ID,
  DEFAULT_PAY_TO,
  DEFAULT_PRICE_ATOMIC,
  DEFAULT_SCAN_PRICE_ATOMIC,
  SCAN_MAX_SOURCE_BYTES,
  USDC,
  type EndpointConfig,
} from "../src/config.js";
import { TRANSFER_WITH_AUTHORIZATION_TYPES } from "../src/x402.js";

/* ================================================================== */
/* Part 1 — engine (fixtures)                                          */
/* ================================================================== */

const fixturesDir = join(import.meta.dirname, "fixtures");

function fixture(name: string): string {
  return readFileSync(join(fixturesDir, name), "utf8");
}

function scanFile(name: string): ScanReport {
  return scanSources({ sources: { [name]: fixture(name) }, solcVersion: "0.8.24" });
}

function ruleIds(report: ScanReport): Set<string> {
  return new Set(report.findings.map((f) => f.rule));
}

function findingFor(report: ScanReport, rule: string): Finding {
  const f = report.findings.find((x) => x.rule === rule);
  assert.ok(f, `expected a "${rule}" finding, got: ${[...ruleIds(report)].join(", ") || "none"}`);
  return f;
}

/** 1-based line number of the first fixture line containing `needle`. */
function findLine(name: string, needle: string): number {
  const idx = fixture(name).split("\n").findIndex((l) => l.includes(needle));
  assert.ok(idx >= 0, `fixture ${name} has a line containing ${needle}`);
  return idx + 1;
}

test("rule library ships 28 concrete rules with sane metadata", () => {
  assert.equal(RULES.length, 28);
  assert.equal(new Set(RULES.map((r) => r.id)).size, 28, "rule ids unique");
  for (const r of RULES) {
    assert.match(r.id, /^[a-z0-9-]+$/, `${r.id}: kebab-case id`);
    assert.ok(["critical", "high", "medium", "low", "info"].includes(r.severity), `${r.id}: severity`);
    assert.ok(r.confidence > 0 && r.confidence <= 1, `${r.id}: confidence in (0,1]`);
    assert.ok(r.why.length > 20 && r.fix.length > 20, `${r.id}: why/fix texts`);
  }
});

test("reentrancy: state written after an unguarded external call (ReentrantVault)", () => {
  const report = scanFile("ReentrantVault.sol");
  const f = findingFor(report, "reentrancy-state-after-external-call");
  assert.equal(f.severity, "high");
  assert.equal(f.line, findLine("ReentrantVault.sol", "msg.sender.call{value: amount}"));
  assert.ok(f.snippet.includes("call{value"), "snippet quotes the call line");
});

test("unchecked low-level call: destructured bool never checked (ReentrantVault)", () => {
  const f = findingFor(scanFile("ReentrantVault.sol"), "unchecked-low-level-call");
  assert.equal(f.severity, "medium");
  assert.ok(f.snippet.includes("sent"));
});

test("unhandled ERC20 transfer return (LazyPayee)", () => {
  const f = findingFor(scanFile("LazyPayee.sol"), "unhandled-transfer-return");
  assert.equal(f.line, findLine("LazyPayee.sol", "token.transfer(msg.sender"));
  assert.ok(f.confidence >= 0.5 && f.confidence <= 1);
});

test("tx.origin used for auth (TxOriginGate)", () => {
  const f = findingFor(scanFile("TxOriginGate.sol"), "tx-origin-auth");
  assert.equal(f.severity, "high");
  assert.equal(f.line, findLine("TxOriginGate.sol", "tx.origin == owner"));
});

test("selfdestruct remnant is critical at the exact line (OldWallet)", () => {
  const f = findingFor(scanFile("OldWallet.sol"), "selfdestruct-remnant");
  assert.equal(f.severity, "critical");
  assert.equal(f.line, findLine("OldWallet.sol", "selfdestruct("));
});

test("delegatecall with a parameter target (LooseExecutor)", () => {
  const f = findingFor(scanFile("LooseExecutor.sol"), "delegatecall-dynamic-target");
  assert.equal(f.severity, "critical");
  assert.equal(f.line, findLine("LooseExecutor.sol", "target.delegatecall(data)"));
});

test("block.timestamp/prevrandao randomness (RiggedRaffle)", () => {
  const f = findingFor(scanFile("RiggedRaffle.sol"), "weak-randomness");
  assert.equal(f.severity, "high");
  assert.equal(f.line, findLine("RiggedRaffle.sol", "block.timestamp"));
});

test("approve race pattern (WildSpender)", () => {
  const f = findingFor(scanFile("WildSpender.sol"), "erc20-approve-race");
  assert.equal(f.line, findLine("WildSpender.sol", "token.approve(spender"));
});

test("setter missing zero-address check (FeeSwitch)", () => {
  const f = findingFor(scanFile("FeeSwitch.sol"), "missing-zero-address-check");
  assert.equal(f.severity, "medium");
  assert.equal(f.line, findLine("FeeSwitch.sol", "function setFeeTo"));
});

test("ERC4626 first-depositor inflation shape (InflatableVault)", () => {
  const f = findingFor(scanFile("InflatableVault.sol"), "erc4626-first-depositor-inflation");
  assert.equal(f.line, findLine("InflatableVault.sol", "function deposit"));
});

test("unbounded loop over a calldata array (Airdropper)", () => {
  const f = findingFor(scanFile("Airdropper.sol"), "unbounded-user-array-loop");
  assert.equal(f.line, findLine("Airdropper.sol", "users.length"));
});

test("parameter shadows a state variable (Registry)", () => {
  const f = findingFor(scanFile("Registry.sol"), "state-variable-shadowing");
  assert.equal(f.line, findLine("Registry.sol", "function record(address owner)"));
  assert.ok(f.why.includes("owner"));
});

test("shadowing also fires across files of one submission", () => {
  const report = scanSources({
    sources: {
      "Base.sol": "pragma solidity 0.8.24;\ncontract Base {\n    uint256 public pot;\n}\n",
      "Other.sol": "pragma solidity 0.8.24;\ncontract Other {\n    function tap(uint256 pot) external {}\n}\n",
    },
  });
  findingFor(report, "state-variable-shadowing");
});

test("push on a memory array (Packer)", () => {
  const f = findingFor(scanFile("Packer.sol"), "memory-array-push");
  assert.equal(f.severity, "low");
  assert.equal(f.line, findLine("Packer.sol", "out.push("));
});

test("uint256 -> uint128 downcast without SafeCast (ShareMath)", () => {
  const f = findingFor(scanFile("ShareMath.sol"), "unsafe-uint-downcast");
  assert.equal(f.line, findLine("ShareMath.sol", "uint128("));
});

test("division before multiplication (Splitter)", () => {
  const f = findingFor(scanFile("Splitter.sol"), "division-before-multiplication");
  assert.equal(f.line, findLine("Splitter.sol", "amount / 100 * 3"));
});

test("fee-on-transfer assumption: nominal credit, no balance diff (FeeTaker)", () => {
  const report = scanFile("FeeTaker.sol");
  const f = findingFor(report, "fee-on-transfer-assumption");
  assert.equal(f.line, findLine("FeeTaker.sol", "token.transferFrom(msg.sender"));
  findingFor(report, "reentrancy-state-after-external-call"); // same body, unguarded write-after-call
});

test("swap with type(uint256).max deadline + CEI ordering (DeadlinelessTrader)", () => {
  const report = scanFile("DeadlinelessTrader.sol");
  const call = findLine("DeadlinelessTrader.sol", "router.swapExactTokensForTokens");
  const deadline = findingFor(report, "swap-missing-deadline");
  assert.equal(deadline.line, call);
  const cei = findingFor(report, "cei-ordering");
  assert.ok(cei.line >= call, "interaction before the state write");
});

test("oracle latestRoundData without updatedAt check (StaleFeed)", () => {
  const f = findingFor(scanFile("StaleFeed.sol"), "oracle-no-staleness-check");
  assert.equal(f.line, findLine("StaleFeed.sol", "feed.latestRoundData()"));
});

test("proxy implementation pitfalls fire as a group (LogicV1)", () => {
  const report = scanFile("LogicV1.sol");
  const guard = findingFor(report, "missing-initializer-guard");
  assert.equal(guard.severity, "high");
  assert.equal(guard.line, findLine("LogicV1.sol", "function initialize"));
  const disable = findingFor(report, "missing-disable-initializers");
  assert.equal(disable.line, findLine("LogicV1.sol", "constructor(uint256 cap)"));
  const ctorWrite = findingFor(report, "impl-constructor-state-write");
  assert.equal(ctorWrite.line, findLine("LogicV1.sol", "admin = msg.sender"));
  const immutable = findingFor(report, "immutable-in-proxy-impl");
  assert.equal(immutable.line, findLine("LogicV1.sol", "immutable hardCap"));
  findingFor(report, "missing-zero-address-check"); // initialize(address admin_) unchecked
});

test("unguarded mint() without access control (FunnyMoney)", () => {
  const f = findingFor(scanFile("FunnyMoney.sol"), "privileged-fn-unprotected");
  assert.equal(f.severity, "high");
  assert.equal(f.line, findLine("FunnyMoney.sol", "function mint"));
});

test("onlyOwner setter emits no event (FeeJar)", () => {
  const f = findingFor(scanFile("FeeJar.sol"), "admin-fn-missing-event");
  assert.equal(f.severity, "low");
  assert.equal(f.line, findLine("FeeJar.sol", "function setFee"));
});

test("modifier performing an external call (OracleGate)", () => {
  const f = findingFor(scanFile("OracleGate.sol"), "modifier-side-effects");
  assert.equal(f.line, findLine("OracleGate.sol", "modifier refreshPrice"));
});

test("floating pragma and missing SPDX (Floating / NoLicense)", () => {
  const floating = findingFor(scanFile("Floating.sol"), "floating-pragma");
  assert.equal(floating.severity, "low");
  assert.equal(floating.line, findLine("Floating.sol", "pragma solidity ^0.8.0;"));
  const spdx = findingFor(scanFile("NoLicense.sol"), "missing-spdx");
  assert.equal(spdx.severity, "info");
  assert.equal(spdx.line, 1);
});

test("clean fixtures produce ZERO findings (false-positive control)", () => {
  const vault = scanFile("CleanVault.sol");
  assert.deepEqual(
    vault.findings.map((f) => `${f.rule}@L${f.line}`),
    [],
  );
  const token = scanFile("CleanToken.sol");
  assert.equal(token.findings.length, 0);
});

test("every rule id in the library is triggered by at least one fixture", () => {
  const all = new Set<string>();
  for (const name of [
    "Airdropper.sol",
    "DeadlinelessTrader.sol",
    "FeeJar.sol",
    "FeeSwitch.sol",
    "FeeTaker.sol",
    "Floating.sol",
    "FunnyMoney.sol",
    "InflatableVault.sol",
    "LazyPayee.sol",
    "LogicV1.sol",
    "LooseExecutor.sol",
    "NoLicense.sol",
    "OldWallet.sol",
    "OracleGate.sol",
    "Packer.sol",
    "ReentrantVault.sol",
    "Registry.sol",
    "RiggedRaffle.sol",
    "ShareMath.sol",
    "Splitter.sol",
    "StaleFeed.sol",
    "TxOriginGate.sol",
    "WildSpender.sol",
  ]) {
    for (const id of ruleIds(scanFile(name))) all.add(id);
  }
  const missing = RULES.filter((r) => !all.has(r.id)).map((r) => r.id);
  assert.deepEqual(missing, [], "every rule covered by the fixture set");
});

test("stats: files/lines counted, rules_run = library size, duration positive", () => {
  const report = scanSources({ sources: { "A.sol": fixture("ReentrantVault.sol"), "B.sol": fixture("Floating.sol") } });
  assert.equal(report.stats.files, 2);
  assert.equal(report.stats.lines, fixture("ReentrantVault.sol").split("\n").length + fixture("Floating.sol").split("\n").length);
  assert.equal(report.stats.rules_run, RULES.length);
  assert.ok(Number.isFinite(report.stats.duration_ms) && report.stats.duration_ms >= 0);
});

test("report shape: disclaimer, limitations, severity ordering, confidence bounds", () => {
  const report = scanSources({ sources: { "A.sol": fixture("OldWallet.sol"), "B.sol": fixture("Floating.sol") } });
  assert.equal(report.disclaimer, "automated pattern scan; not a substitute for a professional audit");
  assert.ok(report.limitations.length >= 3, "honest limitations ship with every report");
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  for (let i = 1; i < report.findings.length; i++) {
    assert.ok(
      order[report.findings[i - 1]!.severity] <= order[report.findings[i]!.severity],
      "findings sorted by severity",
    );
  }
  for (const f of report.findings) {
    assert.ok(f.confidence > 0 && f.confidence <= 1, "confidence in (0,1]");
    assert.ok(f.file && f.line >= 1 && f.snippet.length > 0 && f.why && f.fix, "complete finding fields");
  }
});

test("scanner is deterministic (identical JSON on repeat runs)", () => {
  const a = scanFile("LogicV1.sol");
  const b = scanFile("LogicV1.sol");
  assert.equal(JSON.stringify(a.findings), JSON.stringify(b.findings));
});

test("validateScanRequest rejects the bad shapes the route must gate for free", () => {
  assert.ok(validateScanRequest(undefined));
  assert.ok(validateScanRequest("nope"));
  assert.ok(validateScanRequest({}));
  assert.ok(validateScanRequest({ sources: [] }));
  assert.ok(validateScanRequest({ sources: {} }));
  assert.ok(validateScanRequest({ sources: { "a.sol": 42 } }));
  assert.ok(validateScanRequest({ sources: { "a.sol": "pragma solidity 0.8.24;" }, solcVersion: "latest" }));
  assert.ok(validateScanRequest({ sources: { "big.sol": "x".repeat(SCAN_MAX_SOURCE_BYTES + 1) } }));
  assert.equal(validateScanRequest({ sources: { "a.sol": "pragma solidity 0.8.24;" } }), null);
  assert.equal(validateScanRequest({ sources: { "a.sol": "pragma solidity 0.8.24;" }, solcVersion: "0.8.24" }), null);
});

test("garbage input never crashes the engine (comment/string resilience)", () => {
  const weird = scanSources({
    sources: {
      "weird.sol": '// pragma solidity ^0.8.0; in a comment\npragma solidity 0.8.24;\ncontract C { string public s = "selfdestruct( tx.origin "; }\n',
      "empty.sol": "",
    },
  });
  assert.ok(Array.isArray(weird.findings));
  assert.equal(weird.stats.files, 2); // code in comments/strings is not flagged
  assert.equal(ruleIds(weird).has("selfdestruct-remnant"), false);
  assert.equal(ruleIds(weird).has("tx-origin-auth"), false);
});

/* ================================================================== */
/* Part 2 — POST /scan route (real HTTP, local facilitator, no network) */
/* ================================================================== */

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

function fakeVerdictClient(): VerdictClient {
  return {
    async getChainId() {
      return CHAIN_ID;
    },
    async getTransactionReceipt() {
      return null;
    },
    async getTransaction() {
      return null;
    },
  };
}

let server: Server;
let baseUrl = "";

before(async () => {
  const app = createApp({ config: cfg, clients: [fakeVerdictClient()], facilitator: createLocalFacilitator(), log: () => {} });
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no port");
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(() => new Promise<void>((resolve) => server.close(() => resolve)));

const SCAN_BODY = {
  sources: { "contracts/ReentrantVault.sol": fixture("ReentrantVault.sol") },
  solcVersion: "0.8.24",
};

interface PaymentRequiredHeader {
  x402Version: number;
  error?: string;
  resource: Record<string, unknown>;
  accepts: Array<{ scheme: string; network: string; asset: string; amount: string; payTo: string; maxTimeoutSeconds: number }>;
  extensions?: Record<string, unknown>;
}

async function getScanChallenge(): Promise<PaymentRequiredHeader> {
  const res = await fetch(`${baseUrl}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(SCAN_BODY),
  });
  assert.equal(res.status, 402);
  const raw = res.headers.get("payment-required");
  assert.ok(raw, "PAYMENT-REQUIRED header present");
  return JSON.parse(Buffer.from(raw!, "base64").toString("utf8")) as PaymentRequiredHeader;
}

/** Build + sign a v2 payment for the /scan challenge (throwaway dev key). */
async function signScanPayment(header: PaymentRequiredHeader): Promise<string> {
  const req = header.accepts[0]!;
  const throwaway = privateKeyToAccount(generatePrivateKey());
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
    domain: { name: "USD Coin", version: "2", chainId: CHAIN_ID, verifyingContract: req.asset as `0x${string}` },
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
  return Buffer.from(
    JSON.stringify({ x402Version: 2, resource: header.resource, accepted: req, payload: { signature, authorization } }),
    "utf-8",
  ).toString("base64");
}

test("unpaid POST /scan -> 402 challenge priced 100000 atomic USDC ($1.00)", async () => {
  const header = await getScanChallenge();
  assert.equal(header.x402Version, 2);
  const a = header.accepts[0]!;
  assert.equal(a.scheme, "exact");
  assert.equal(a.network, "eip155:8453");
  assert.equal(a.amount, "100000", "scan price is 100x the /verify probe price");
  assert.equal(a.asset, USDC);
  assert.equal(a.payTo, DEFAULT_PAY_TO);
  assert.equal((header.resource as { url: string }).url, "https://proto.example/scan");
});

test("the /scan challenge carries the bazaar discovery declaration (input/output schemas)", async () => {
  const header = await getScanChallenge();
  const bazaar = header.extensions?.bazaar as { info?: Record<string, unknown>; schema?: Record<string, unknown> } | undefined;
  assert.ok(bazaar, "bazaar extension declared for /scan");
  assert.ok(bazaar.info && bazaar.schema);
  const body = JSON.stringify(bazaar);
  assert.ok(body.includes("sources"), "input schema names sources");
  assert.ok(body.includes("findings"), "output example shows findings");
});

test("oversized sources are rejected FREE with 400 (no payment demanded)", async () => {
  const res = await fetch(`${baseUrl}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ sources: { "big.sol": "x".repeat(SCAN_MAX_SOURCE_BYTES + 1) } }),
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("payment-required"), null, "no 402 challenge on a free rejection");
  const body = (await res.json()) as { error?: string };
  assert.match(body.error ?? "", /too large/i);
});

test("malformed scan bodies are rejected FREE with 400", async () => {
  for (const bad of [JSON.stringify({}), JSON.stringify({ sources: 7 }), JSON.stringify({ sources: { "a.sol": 1 } }), JSON.stringify({ sources: { "a.sol": "pragma solidity 0.8.24;" }, solcVersion: "oz" })]) {
    const res = await fetch(`${baseUrl}/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: bad });
    assert.equal(res.status, 400);
    assert.equal(res.headers.get("payment-required"), null);
  }
  const empty = await fetch(`${baseUrl}/scan`, { method: "POST" }); // no body at all
  assert.equal(empty.status, 400);
});

test("a JSON envelope over the parser limit is rejected free with 400 (too large)", async () => {
  const res = await fetch(`${baseUrl}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ sources: { "huge.sol": "x".repeat(1024 * 1024 + 4096) } }),
  });
  assert.equal(res.status, 400);
  const body = (await res.json()) as { error?: string };
  assert.match(body.error ?? "", /too large/i);
});

test("GET /scan is not a route -> JSON 404", async () => {
  const res = await fetch(`${baseUrl}/scan`);
  assert.equal(res.status, 404);
  const body = (await res.json()) as { error?: string };
  assert.equal(body.error, "not found");
});

test("full paid flow: 402 -> sign -> 200 scan report + PAYMENT-RESPONSE header", async () => {
  const header = await getScanChallenge();
  const payment = await signScanPayment(header);

  const res = await fetch(`${baseUrl}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json", "PAYMENT-SIGNATURE": payment },
    body: JSON.stringify(SCAN_BODY),
  });
  assert.equal(res.status, 200);
  assert.ok(res.headers.get("payment-response"), "PAYMENT-RESPONSE receipt present");

  const report = (await res.json()) as ScanReport;
  assert.ok(Array.isArray(report.findings) && report.findings.length > 0);
  assert.ok(report.findings.some((f) => f.rule === "reentrancy-state-after-external-call"));
  assert.equal(report.stats.files, 1);
  assert.equal(report.stats.rules_run, RULES.length);
  assert.equal(report.disclaimer, "automated pattern scan; not a substitute for a professional audit");
  for (const f of report.findings) {
    assert.equal(f.file, "contracts/ReentrantVault.sol");
    assert.ok(f.line >= 1 && f.snippet && f.why && f.fix);
  }
});

test("paid flow on a clean file returns zero findings (paid for a real answer, not noise)", async () => {
  const header = await getScanChallenge();
  const payment = await signScanPayment(header);
  const res = await fetch(`${baseUrl}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json", "PAYMENT-SIGNATURE": payment },
    body: JSON.stringify({ sources: { "CleanVault.sol": fixture("CleanVault.sol") } }),
  });
  assert.equal(res.status, 200);
  const report = (await res.json()) as ScanReport;
  assert.deepEqual(report.findings, []);
  assert.equal(report.stats.files, 1);
});

test("garbage PAYMENT-SIGNATURE -> 402 challenge again (SDK semantics on /scan)", async () => {
  const res = await fetch(`${baseUrl}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json", "PAYMENT-SIGNATURE": "%%%not-base64%%%" },
    body: JSON.stringify(SCAN_BODY),
  });
  assert.equal(res.status, 402);
  assert.ok(res.headers.get("payment-required"));
});
