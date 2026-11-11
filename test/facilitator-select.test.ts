/**
 * Hosted-facilitator pre-wiring tests (all offline, no network):
 *   - env selection: FACILITATOR_URL set -> hosted client; unset -> local
 *     verify-only facilitator + the honest cannot-earn startup warning;
 *     CDP credentials validated as both-or-neither and url-required.
 *   - CDP bearer JWT: correct EdDSA header/claims (kid/sub/iss/aud/uri,
 *     120 s window) per facilitator path with the right METHOD, and an
 *     Ed25519-verifiable signature minted from a throwaway key generated here.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, verify as edVerify } from "node:crypto";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { DEFAULT_PAY_TO, DEFAULT_PRICE_ATOMIC, DEFAULT_SCAN_PRICE_ATOMIC, loadConfig, type EndpointConfig } from "../src/config.js";
import { LOCAL_FACILITATOR_WARNING, mintCdpBearerToken, selectFacilitator } from "../src/facilitator-select.js";

const BASE_ENV = {
  PORT: "3000",
  PAY_TO: DEFAULT_PAY_TO,
};

function cfg(overrides: Record<string, string | undefined>): EndpointConfig {
  return loadConfig({ ...BASE_ENV, ...overrides });
}

/** A CDP-format key: 64 bytes = 32-byte seed || 32-byte public key, base64. */
function throwawayCdpSecret(): { secret: string; verifyKey: ReturnType<typeof generateKeyPairSync>["publicKey"] } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(16);
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  assert.equal(seed.length, 32);
  return { secret: Buffer.concat([seed, pub]).toString("base64"), verifyKey: publicKey };
}

function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signingInput: Buffer; signature: Buffer } {
  const [h, p, s] = token.split(".");
  assert.ok(h && p && s, "JWT has three segments");
  return {
    header: JSON.parse(Buffer.from(h, "base64url").toString("utf8")),
    payload: JSON.parse(Buffer.from(p, "base64url").toString("utf8")),
    signingInput: Buffer.from(`${h}.${p}`),
    signature: Buffer.from(s, "base64url"),
  };
}

test("loadConfig: FACILITATOR_URL selects the hosted facilitator URL", () => {
  const c = cfg({ FACILITATOR_URL: "https://api.cdp.coinbase.com/platform/v2/x402/" });
  assert.equal(c.facilitatorUrl, "https://api.cdp.coinbase.com/platform/v2/x402");
  assert.equal(c.facilitatorApiKeyId, null);
  assert.equal(c.facilitatorApiKey, null);
});

test("loadConfig: unset FACILITATOR_URL keeps the verify-only default", () => {
  const c = cfg({});
  assert.equal(c.facilitatorUrl, null);
  assert.equal(c.facilitatorApiKeyId, null);
  assert.equal(c.facilitatorApiKey, null);
});

test("loadConfig: CDP credentials are both-or-neither", () => {
  assert.throws(() => cfg({ CDP_API_KEY: "abc" }), /CDP_API_KEY and CDP_API_KEY_ID must be set together/);
  assert.throws(() => cfg({ CDP_API_KEY_ID: "kid" }), /CDP_API_KEY and CDP_API_KEY_ID must be set together/);
  const both = cfg({ FACILITATOR_URL: "https://f.example", CDP_API_KEY_ID: "kid", CDP_API_KEY: "abc" });
  assert.equal(both.facilitatorApiKeyId, "kid");
  assert.equal(both.facilitatorApiKey, "abc");
});

test("loadConfig: CDP credentials without FACILITATOR_URL fail fast", () => {
  assert.throws(
    () => cfg({ CDP_API_KEY_ID: "kid", CDP_API_KEY: "abc" }),
    /only take effect with FACILITATOR_URL/,
  );
});

test("selectFacilitator: env set -> hosted HTTPFacilitatorClient, no warning", () => {
  const sel = selectFacilitator(cfg({ FACILITATOR_URL: "https://api.cdp.coinbase.com/platform/v2/x402" }));
  assert.equal(sel.hosted, true);
  assert.equal(sel.warning, null);
  assert.ok(sel.facilitator instanceof HTTPFacilitatorClient);
  assert.equal((sel.facilitator as HTTPFacilitatorClient).url, "https://api.cdp.coinbase.com/platform/v2/x402");
});

test("selectFacilitator: env unset -> local verify-only facilitator + cannot-earn warning", () => {
  const sel = selectFacilitator(cfg({}));
  assert.equal(sel.hosted, false);
  assert.equal(typeof sel.facilitator.verify, "function"); // local FacilitatorClient shape
  assert.equal(typeof sel.facilitator.settle, "function");
  assert.match(sel.warning ?? "", /FACILITATOR_URL is not set/);
  assert.match(sel.warning ?? "", /Settlement is DISABLED/i);
  assert.match(sel.warning ?? "", /CANNOT EARN/);
  assert.match(LOCAL_FACILITATOR_WARNING, /CDP_API_KEY_ID and CDP_API_KEY/);
});

test("hosted facilitator: CDP credentials -> per-path EdDSA bearer JWTs with the right METHOD+uri", async () => {
  const { secret, verifyKey } = throwawayCdpSecret();
  const sel = selectFacilitator(
    cfg({ FACILITATOR_URL: "https://api.cdp.coinbase.com/platform/v2/x402", CDP_API_KEY_ID: "test-kid", CDP_API_KEY: secret }),
  );
  assert.ok(sel.facilitator instanceof HTTPFacilitatorClient);
  const client = sel.facilitator as HTTPFacilitatorClient;

  const expectUri = { verify: "POST", settle: "POST", supported: "GET" } as const;
  for (const path of ["verify", "settle", "supported"] as const) {
    const { headers } = await client.createAuthHeaders(path);
    const token = headers.Authorization ?? "";
    assert.match(token, /^Bearer /);
    const { header, payload, signingInput, signature } = decodeJwt(token.slice("Bearer ".length));
    assert.equal(header.alg, "EdDSA");
    assert.equal(header.typ, "JWT");
    assert.equal(header.kid, "test-kid");
    assert.equal(payload.sub, "test-kid");
    assert.equal(payload.iss, "cdp");
    assert.deepEqual(payload.aud, ["cdp_service"]);
    assert.equal(payload.uri, `${expectUri[path]} api.cdp.coinbase.com /platform/v2/x402/${path}`);
    const nbf = payload.nbf as number;
    assert.equal((payload.exp as number) - nbf, 120);
    assert.ok(typeof header.nonce === "string" && header.nonce.length > 0);
    assert.ok(edVerify(null, signingInput, verifyKey, signature), `${path} JWT signature verifies (Ed25519)`);
  }
});

test("mintCdpBearerToken: rejects a malformed secret", () => {
  assert.throws(
    () => mintCdpBearerToken({ apiKeyId: "k", apiKeySecret: Buffer.from("short").toString("base64"), method: "POST", host: "h", path: "/p" }),
    /64-byte/,
  );
});

test("config defaults unchanged by the new wiring", () => {
  const c = cfg({});
  assert.equal(c.priceAtomic, DEFAULT_PRICE_ATOMIC);
  assert.equal(c.scanPriceAtomic, DEFAULT_SCAN_PRICE_ATOMIC);
  assert.equal(c.payTo, DEFAULT_PAY_TO);
});
