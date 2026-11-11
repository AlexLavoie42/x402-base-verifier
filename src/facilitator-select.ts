/**
 * Env-driven facilitator selection for the runnable entry point — the
 * pre-wiring that makes going live PURELY env-vars + one deploy click:
 *
 *   FACILITATOR_URL set (e.g. Coinbase CDP
 *   https://api.cdp.coinbase.com/platform/v2/x402)  -> HTTPFacilitatorClient
 *   against it: the hosted facilitator verifies AND settles on-chain, so the
 *   rail can earn. When CDP_API_KEY_ID + CDP_API_KEY are also set, every
 *   facilitator call carries the CDP bearer JWT minted here per request
 *   (EdDSA/Ed25519, uri-bound, 120 s — exactly the recipe in CDP's
 *   authentication docs), because @x402/core 2.30's FacilitatorConfig has no
 *   apiKey field, only createAuthHeaders keyed by facilitator path.
 *
 *   FACILITATOR_URL unset -> the in-process verify-only facilitator (honest
 *   dev default; see src/local-facilitator.ts) plus a startup WARNING that
 *   settlement is disabled and the rail cannot earn.
 */
import { createPrivateKey, randomBytes, sign as edSign } from "node:crypto";
import { HTTPFacilitatorClient } from "@x402/core/server";
import type { FacilitatorClient } from "@x402/core/server";
import type { EndpointConfig } from "./config.js";
import { createLocalFacilitator } from "./local-facilitator.js";
import type { OnChainCheckResult } from "./payment.js";

/** DER prefix that wraps a raw 32-byte Ed25519 seed as a PKCS#8 private key. */
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** CDP bearer tokens are valid for 120 seconds (CDP authentication docs). */
const CDP_TOKEN_TTL_SECONDS = 120;

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export interface CdpBearerTokenInput {
  /** CDP API key id (JWT "kid"/"sub") — env CDP_API_KEY_ID. */
  apiKeyId: string;
  /** CDP API key secret: base64 of 64 bytes (32-byte seed || 32-byte public key) — env CDP_API_KEY. */
  apiKeySecret: string;
  /** Request method the token is bound to ("POST" | "GET"). */
  method: string;
  /** Request host the token is bound to (e.g. api.cdp.coinbase.com). */
  host: string;
  /** Request path the token is bound to (e.g. /platform/v2/x402/verify). */
  path: string;
  /** Injectable clock (tests). */
  now?: () => number;
  /** Injectable nonce (tests). */
  nonce?: () => string;
}

/**
 * Mint the CDP bearer JWT for one facilitator request: EdDSA over Ed25519,
 * header { alg, typ, kid, nonce }, claims { sub, iss: "cdp", aud, nbf, exp,
 * uri: "METHOD host path" }, base64url without padding. The 64-byte secret is
 * the seed (first 32 bytes) plus the public key; node:crypto signs with the
 * seed — no extra dependency needed.
 */
export function mintCdpBearerToken(input: CdpBearerTokenInput): string {
  // accept standard base64 or base64url, ignore whitespace
  const normalized = input.apiKeySecret.trim().replace(/-/g, "+").replace(/_/g, "/");
  const decoded = Buffer.from(normalized, "base64");
  if (decoded.length !== 64) {
    throw new Error("CDP_API_KEY must be the base64 of a 64-byte CDP API key secret (seed || public key)");
  }
  const seed = decoded.subarray(0, 32);
  const key = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
  const nbf = (input.now ?? (() => Math.floor(Date.now() / 1000)))();
  const header = { alg: "EdDSA", typ: "JWT", kid: input.apiKeyId, nonce: input.nonce?.() ?? randomBytes(8).toString("hex") };
  const payload = {
    sub: input.apiKeyId,
    iss: "cdp",
    aud: ["cdp_service"],
    nbf,
    exp: nbf + CDP_TOKEN_TTL_SECONDS,
    uri: `${input.method} ${input.host} ${input.path}`,
  };
  const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(JSON.stringify(payload)))}`;
  const signature = edSign(null, Buffer.from(signingInput), key);
  return `${signingInput}.${b64url(signature)}`;
}

/**
 * Build the hosted facilitator client. When CDP credentials are configured,
 * each facilitator path gets a freshly minted, method/URI-bound bearer JWT
 * (the HTTPFacilitatorClient re-invokes createAuthHeaders per request, so the
 * 120 s tokens never go stale). Without credentials the client sends no auth
 * headers — fine for facilitators that don't require them.
 */
export function createHostedFacilitator(cfg: EndpointConfig): HTTPFacilitatorClient {
  if (cfg.facilitatorUrl === null) throw new Error("createHostedFacilitator requires facilitatorUrl to be set");
  if (cfg.facilitatorApiKey === null || cfg.facilitatorApiKeyId === null) {
    return new HTTPFacilitatorClient({ url: cfg.facilitatorUrl });
  }
  const url = new URL(cfg.facilitatorUrl);
  const basePath = url.pathname.replace(/\/+$/, "");
  const bearer = (method: "POST" | "GET", op: string) =>
    mintCdpBearerToken({
      apiKeyId: cfg.facilitatorApiKeyId!,
      apiKeySecret: cfg.facilitatorApiKey!,
      method,
      host: url.host,
      path: `${basePath}/${op}`,
    });
  return new HTTPFacilitatorClient({
    url: cfg.facilitatorUrl,
    // methods per @x402/core's HTTPFacilitatorClient: verify/settle -> POST, supported -> GET
    createAuthHeaders: async () => ({
      verify: { Authorization: `Bearer ${bearer("POST", "verify")}` },
      settle: { Authorization: `Bearer ${bearer("POST", "settle")}` },
      supported: { Authorization: `Bearer ${bearer("GET", "supported")}` },
    }),
  });
}

/** Honest startup warning when the verify-only default is running. */
export const LOCAL_FACILITATOR_WARNING =
  "WARNING: FACILITATOR_URL is not set — running the in-process verify-only facilitator. " +
  "Settlement is DISABLED: payments verify but are never collected on-chain, so this rail CANNOT EARN. " +
  "To enable settlement, set FACILITATOR_URL (e.g. https://api.cdp.coinbase.com/platform/v2/x402) " +
  "plus CDP_API_KEY_ID and CDP_API_KEY, then redeploy.";

export interface FacilitatorSelection {
  facilitator: FacilitatorClient;
  /** true when wired to a hosted facilitator over HTTP (settlement possible). */
  hosted: boolean;
  /** Startup warning to log when hosted is false; null when hosted. */
  warning: string | null;
}

export interface SelectFacilitatorDeps {
  /**
   * Read-only on-chain authorizationState check for the local (default)
   * facilitator. The entry point wires makeRpcSettlementCheck; tests inject
   * nothing (verification-only, no network).
   */
  settlementCheck?: (from: string, nonce: string) => Promise<OnChainCheckResult>;
}

/** Select the facilitator from config: hosted when FACILITATOR_URL is set, local otherwise. */
export function selectFacilitator(cfg: EndpointConfig, deps: SelectFacilitatorDeps = {}): FacilitatorSelection {
  if (cfg.facilitatorUrl !== null) {
    return { facilitator: createHostedFacilitator(cfg), hosted: true, warning: null };
  }
  return {
    facilitator: createLocalFacilitator({ settlementCheck: deps.settlementCheck }),
    hosted: false,
    warning: LOCAL_FACILITATOR_WARNING,
  };
}
