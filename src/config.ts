/**
 * x402-endpoint config — constants + env loading. Nothing secret.
 *
 * The one fact everything hinges on: the EIP-712 domain of native USDC on
 * Base is { name: "USD Coin", version: "2", chainId: 8453 }. This is
 * confirmed against the live contract by `npm run domain-check` (read-only
 * DOMAIN_SEPARATOR() comparison) and matches the official x402 v2 SDK
 * default-asset table (@x402/evm mechanisms/evm/src/defaultAssets.ts).
 */

export const CHAIN_ID = 8453;
export const NETWORK = "base"; // legacy v1 network identifier (src/x402.ts library)
/** x402 v2 CAIP-2 network identifier for Base mainnet. */
export const NETWORK_CAIP = "eip155:8453" as const;
export const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;
export const USDC_DECIMALS = 6;
export const ETH_DECIMALS = 18;

/** Receive-only wallet of the ZERO_CAPITAL operation (STATE.md). */
export const DEFAULT_PAY_TO = "0x696344061b0f4CcFbA0b48a8390330C6b2525531";

/** Start price: 10000 atomic USDC = $0.01 (USDC has 6 decimals). */
export const DEFAULT_PRICE_ATOMIC = 10_000n;

/**
 * Scan price: 100000 atomic USDC = $1.00 — deeper per-request work than the
 * $0.01 /verify verdict, so the /scan route carries its own price (per-route
 * configurable via SCAN_PRICE_ATOMIC).
 */
export const DEFAULT_SCAN_PRICE_ATOMIC = 100_000n;

/** How long a signed EIP-3009 authorization may remain valid (challenge field). */
export const MAX_TIMEOUT_SECONDS = 30;

export const RESOURCE_PATH = "/verify";
export const SCAN_PATH = "/scan";

/** Free-reject thresholds for POST /scan (the body is JSON, sources are raw text). */
export const SCAN_MAX_SOURCE_BYTES = 200 * 1024; // ~200 KB of Solidity source total
export const SCAN_MAX_FILES = 200;
/** JSON body parser limit for /scan: room for 200 KB of escaped source + envelope. */
export const SCAN_JSON_LIMIT = "1mb";

/**
 * Coinbase's hosted facilitator (the SDK's own default). NOTE: as of 2026-11
 * it does NOT support Base mainnet (eip155:8453) — only Base Sepolia and some
 * non-EVM chains — which is why the default here is the in-process verify-only
 * facilitator and this URL is only used when FACILITATOR_URL is set explicitly.
 */
export const DEFAULT_FACILITATOR_URL = "https://x402.org/facilitator";

export const SERVICE_NAME = "base-payment-verification";
export const SERVICE_TAGS = ["base", "usdc", "payments", "verification", "x402"];

export const SERVICE_DESCRIPTION =
  "Base payment verification: did transaction 0x… transfer >= X USDC (or ETH) to address 0x…? Structured verdict over public Base RPCs.";

export const SCAN_SERVICE_NAME = "solidity-pre-audit-scanner";
export const SCAN_SERVICE_TAGS = ["solidity", "security", "audit", "smart-contracts", "x402"];

export const SCAN_SERVICE_DESCRIPTION =
  "Solidity pre-audit scanner: 28 deterministic pattern rules (reentrancy shapes, ERC4626 share inflation, proxy-initialization pitfalls, oracle staleness, weak randomness, unsafe casts, ...) with severity, confidence and line numbers. Fully offline; no compiler, no network.";

/**
 * Public-RPC fallback list with the quirks learned in the field
 * (EVIDENCE/mainnet-readonly-check.txt, same as tools/base-watchdog):
 *   - base.drpc.org:   allows everything we need (receipts, txs) — first choice
 *   - mainnet.base.org: fine for eth_getTransactionReceipt/eth_getTransaction
 *                       (its documented quirk is 429s on address-less
 *                       eth_getLogs, which this service never does)
 * This endpoint only ever makes read-only calls; a facilitator settles.
 */
export const DEFAULT_RPC_URLS = ["https://base.drpc.org", "https://mainnet.base.org"];

export interface EndpointConfig {
  port: number;
  baseUrl: string; // advertised resource origin, e.g. https://api.example.com
  rpcUrls: string[];
  priceAtomic: bigint;
  /** Separate price for POST /scan (default 100000 atomic = $1.00). */
  scanPriceAtomic: bigint;
  payTo: `0x${string}`;
  maxTimeoutSeconds: number;
  /**
   * x402 v2 facilitator base URL (verify/settle/supported), or null to use the
   * in-process verify-only facilitator (the receive-only default — see
   * src/local-facilitator.ts for why the hosted default doesn't fit).
   */
  facilitatorUrl: string | null;
  /**
   * CDP API key id (JWT kid/sub) for authenticating with a hosted facilitator
   * (env CDP_API_KEY_ID), or null. Only meaningful with facilitatorUrl; the
   * pair must be set together with CDP_API_KEY.
   */
  facilitatorApiKeyId: string | null;
  /**
   * CDP API key secret (base64 of 64 bytes: seed || public key; env
   * CDP_API_KEY), or null. Used to mint the per-request EdDSA bearer JWT —
   * see src/facilitator-select.ts.
   */
  facilitatorApiKey: string | null;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): EndpointConfig {
  const port = Number(env.PORT ?? 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be an integer from 1 to 65535");
  const rpcUrls = (env.RPC_URLS ?? DEFAULT_RPC_URLS.join(",")).split(",").map((s) => s.trim()).filter(Boolean);
  if (!rpcUrls.length || rpcUrls.some((s) => !/^https?:\/\//.test(s))) throw new Error("RPC_URLS must contain HTTP(S) URLs");
  const priceAtomic = BigInt(env.PRICE_ATOMIC ?? DEFAULT_PRICE_ATOMIC);
  if (priceAtomic < 1n) throw new Error("PRICE_ATOMIC must be a positive integer (atomic USDC units)");
  const scanPriceAtomic = BigInt(env.SCAN_PRICE_ATOMIC ?? DEFAULT_SCAN_PRICE_ATOMIC);
  if (scanPriceAtomic < 1n) throw new Error("SCAN_PRICE_ATOMIC must be a positive integer (atomic USDC units)");
  const payTo = (env.PAY_TO ?? DEFAULT_PAY_TO) as `0x${string}`;
  if (!/^0x[0-9a-fA-F]{40}$/.test(payTo)) throw new Error("PAY_TO must be a 0x… 20-byte address");
  const facilitatorUrl = env.FACILITATOR_URL ? env.FACILITATOR_URL.replace(/\/+$/, "") : null;
  if (facilitatorUrl !== null && !/^https?:\/\//.test(facilitatorUrl)) {
    throw new Error("FACILITATOR_URL must be an HTTP(S) URL");
  }
  const facilitatorApiKeyId = env.CDP_API_KEY_ID?.trim() || null;
  const facilitatorApiKey = env.CDP_API_KEY?.trim() || null;
  if ((facilitatorApiKeyId === null) !== (facilitatorApiKey === null)) {
    throw new Error("CDP_API_KEY and CDP_API_KEY_ID must be set together (the CDP bearer JWT needs both the secret and its key id)");
  }
  if (facilitatorApiKey !== null && facilitatorUrl === null) {
    throw new Error("CDP_API_KEY/CDP_API_KEY_ID only take effect with FACILITATOR_URL — set FACILITATOR_URL too, or unset the CDP vars");
  }
  return {
    port,
    baseUrl: (env.BASE_URL ?? `http://localhost:${port}`).replace(/\/+$/, ""),
    rpcUrls,
    priceAtomic,
    scanPriceAtomic,
    payTo,
    maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
    facilitatorUrl,
    facilitatorApiKeyId,
    facilitatorApiKey,
  };
}
