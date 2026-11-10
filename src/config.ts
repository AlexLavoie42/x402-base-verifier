/**
 * x402-endpoint config — constants + env loading. Nothing secret.
 *
 * The one fact everything hinges on: the EIP-712 domain of native USDC on
 * Base is { name: "USD Coin", version: "2", chainId: 8453 }. This is
 * confirmed against the live contract by `npm run domain-check` (read-only
 * DOMAIN_SEPARATOR() comparison) and matches the official x402
 * chain config (coinbase/x402, types/shared/evm/config.ts).
 */

export const CHAIN_ID = 8453;
export const NETWORK = "base"; // x402 network identifier for Base mainnet
export const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;
export const USDC_DECIMALS = 6;
export const ETH_DECIMALS = 18;

/** Receive-only wallet of the ZERO_CAPITAL operation (STATE.md). */
export const DEFAULT_PAY_TO = "0x696344061b0f4CcFbA0b48a8390330C6b2525531";

/** Start price: 10000 atomic USDC = $0.01 (USDC has 6 decimals). */
export const DEFAULT_PRICE_ATOMIC = 10_000n;

/** How long a signed EIP-3009 authorization may remain valid (challenge field). */
export const MAX_TIMEOUT_SECONDS = 30;

export const RESOURCE_PATH = "/verify";

export const SERVICE_DESCRIPTION =
  "Base payment verification: did transaction 0x… transfer >= X USDC (or ETH) to address 0x…? Structured verdict over public Base RPCs.";

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
  payTo: `0x${string}`;
  maxTimeoutSeconds: number;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): EndpointConfig {
  const port = Number(env.PORT ?? 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be an integer from 1 to 65535");
  const rpcUrls = (env.RPC_URLS ?? DEFAULT_RPC_URLS.join(",")).split(",").map((s) => s.trim()).filter(Boolean);
  if (!rpcUrls.length || rpcUrls.some((s) => !/^https?:\/\//.test(s))) throw new Error("RPC_URLS must contain HTTP(S) URLs");
  const priceAtomic = BigInt(env.PRICE_ATOMIC ?? DEFAULT_PRICE_ATOMIC);
  if (priceAtomic < 1n) throw new Error("PRICE_ATOMIC must be a positive integer (atomic USDC units)");
  const payTo = (env.PAY_TO ?? DEFAULT_PAY_TO) as `0x${string}`;
  if (!/^0x[0-9a-fA-F]{40}$/.test(payTo)) throw new Error("PAY_TO must be a 0x… 20-byte address");
  return {
    port,
    baseUrl: (env.BASE_URL ?? `http://localhost:${port}`).replace(/\/+$/, ""),
    rpcUrls,
    priceAtomic,
    payTo,
    maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
  };
}
