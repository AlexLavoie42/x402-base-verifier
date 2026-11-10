/**
 * x402 v1 wire types and codecs (HTTP transport).
 * Field names and shapes follow the official spec:
 *   https://github.com/coinbase/x402/blob/main/specs/x402-specification-v1.md
 *   https://github.com/coinbase/x402/blob/main/specs/transports-v1/http.md
 *   The official TS client encodes the X-PAYMENT header as standard base64
 *   (safeBase64Encode = btoa / Buffer.toString("base64")). We decode
 *   permissively (standard and URL-safe alphabets) and emit standard base64.
 */
import type { EndpointConfig } from "./config.js";
import { NETWORK, RESOURCE_PATH, SERVICE_DESCRIPTION, USDC } from "./config.js";

export interface PaymentRequirements {
  scheme: "exact";
  network: typeof NETWORK;
  /** Required payment amount in atomic token units, decimal string. */
  maxAmountRequired: string;
  /** Token contract address. */
  asset: string;
  /** Recipient wallet address. */
  payTo: string;
  /** URL of the protected resource. */
  resource: string;
  description: string;
  mimeType: string;
  outputSchema: null;
  maxTimeoutSeconds: number;
  /** EIP-712 domain name/version of the token — what the client signs with. */
  extra: { name: string; version: string };
}

export interface PaymentRequirementsResponse {
  x402Version: 1;
  error: string;
  accepts: [PaymentRequirements];
}

/** EIP-3009 transferWithAuthorization parameters (all decimal/hex strings). */
export interface Authorization {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
}

export interface PaymentPayload {
  x402Version: number;
  scheme: string;
  network: string;
  payload: { signature: string; authorization: Authorization };
}

export interface SettlementResponse {
  success: boolean;
  errorReason?: string;
  transaction: string;
  network: string;
  payer: string;
}

export function buildRequirements(cfg: EndpointConfig, resource: string): PaymentRequirements {
  return {
    scheme: "exact",
    network: NETWORK,
    maxAmountRequired: cfg.priceAtomic.toString(),
    asset: USDC,
    payTo: cfg.payTo,
    resource,
    description: SERVICE_DESCRIPTION,
    mimeType: "application/json",
    outputSchema: null,
    maxTimeoutSeconds: cfg.maxTimeoutSeconds,
    extra: { name: EIP712_NAME, version: EIP712_VERSION },
  };
}

export function buildChallenge(cfg: EndpointConfig, resource: string): PaymentRequirementsResponse {
  return {
    x402Version: 1,
    error: "X-PAYMENT header is required",
    accepts: [buildRequirements(cfg, resource)],
  };
}

/** Decode X-PAYMENT. Throws Error("malformed payment payload") variants on bad input. */
export function decodePaymentHeader(header: string): PaymentPayload {
  const normalized = header.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  let json: string;
  try {
    json = Buffer.from(normalized, "base64").toString("utf-8");
  } catch {
    throw new Error("malformed payment payload: not base64");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("malformed payment payload: not JSON");
  }
  const p = parsed as Partial<PaymentPayload> & { payload?: { signature?: unknown; authorization?: unknown } };
  if (
    typeof p !== "object" || p === null ||
    typeof p.x402Version !== "number" || typeof p.scheme !== "string" || typeof p.network !== "string" ||
    typeof p.payload !== "object" || p.payload === null ||
    typeof p.payload.signature !== "string" || typeof p.payload.authorization !== "object" || p.payload.authorization === null
  ) {
    throw new Error("malformed payment payload: wrong shape");
  }
  const a = p.payload.authorization as Partial<Record<keyof Authorization, unknown>>;
  for (const k of ["from", "to", "value", "validAfter", "validBefore", "nonce"] as const) {
    if (typeof a[k] !== "string") throw new Error(`malformed payment payload: authorization.${k} must be a string`);
  }
  return p as PaymentPayload;
}

/** Encode the X-PAYMENT-RESPONSE settlement header (standard base64). */
export function encodeSettlementResponse(s: SettlementResponse): string {
  return Buffer.from(JSON.stringify(s), "utf-8").toString("base64");
}

// ---------------------------------------------------------------------------
// EIP-3009 / EIP-712 constants — the domain the verifier recovers against.
// ---------------------------------------------------------------------------

export const EIP712_NAME = "USD Coin";
export const EIP712_VERSION = "2";

export const USDC_EIP712_DOMAIN = {
  name: EIP712_NAME,
  version: EIP712_VERSION,
  chainId: 8453,
  verifyingContract: USDC,
} as const;

export const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

export function buildTypedData(auth: Authorization) {
  // wire format is all-strings; viem wants typed values (bigint for uints)
  return {
    domain: USDC_EIP712_DOMAIN,
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
    primaryType: "TransferWithAuthorization" as const,
    message: {
      from: auth.from as `0x${string}`,
      to: auth.to as `0x${string}`,
      value: BigInt(auth.value),
      validAfter: BigInt(auth.validAfter),
      validBefore: BigInt(auth.validBefore),
      nonce: auth.nonce as `0x${string}`,
    },
  };
}
