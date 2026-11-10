/**
 * In-process, verify-only FacilitatorClient — the DEFAULT payment rail for
 * this deployment, and the same posture the v1 hand-rolled gate had:
 *
 *  WHY: the operation is receive-only (no key, no signing, no transactions),
 *  and Coinbase's hosted facilitator (https://x402.org/facilitator) does NOT
 *  support Base mainnet (eip155:8453) as of 2026-11 — only Base Sepolia and
 *  some non-EVM chains (probed live; see MIGRATION.md). So the middleware's
 *  standard facilitator-verify path is served by this local client:
 *
 *   verify()  full off-chain EIP-3009 validation, exactly what a facilitator
 *             does first: EIP-712 signature recovery against the token domain
 *             declared by the requirements (extra.name/version, chainId 8453,
 *             asset as verifyingContract — recovering against that domain
 *             also binds the signature to the USDC contract), payTo / amount /
 *             validity-window checks, an in-memory nonce replay guard, and an
 *             optional read-only on-chain authorizationState check
 *             (wire `makeRpcSettlementCheck` from src/settlement.ts).
 *   settle()  burns the nonce and returns success with an EMPTY transaction.
 *             Nothing is ever broadcast — the signed authorization simply
 *             expires unclaimed at validBefore; tools/base-watchdog watching
 *             USDC into payTo is the settlement observer. (A hosted
 *             facilitator would settle on-chain for a fee when one supports
 *             Base mainnet; point FACILITATOR_URL at it to switch.)
 *   getSupported() advertises exactly what the routes declare: x402 v2
 *             "exact" on Base mainnet.
 *
 * Tests inject this with no on-chain check; the runnable entry wires the
 * read-only RPC check. It never creates a transaction in any configuration.
 */
import { getAddress, recoverTypedDataAddress } from "viem";
import type { FacilitatorClient } from "@x402/core/server";
import type { PaymentPayload, PaymentRequirements, VerifyResponse } from "@x402/core/types";
import { CHAIN_ID } from "./config.js";
import { TRANSFER_WITH_AUTHORIZATION_TYPES } from "./x402.js";
import type { OnChainCheckResult } from "./payment.js";

/** Minimal v2 wire shapes the local facilitator deals with (subset of @x402/core/types). */
interface EvmExactPayload {
  authorization: {
    from: string;
    to: string;
    value: string;
    validAfter: string;
    validBefore: string;
    nonce: string;
  };
  signature: string;
}

export interface LocalFacilitatorOptions {
  /** Injectable clock (tests). */
  now?: () => number;
  /** Read-only on-chain authorizationState check (EIP-3009 state map). Default: skip. */
  settlementCheck?: (from: string, nonce: string) => Promise<OnChainCheckResult>;
}

export interface LocalFacilitator extends FacilitatorClient {
  /** Nonces consumed so far (verified once). Exposed for assertions. */
  readonly seenNonces: ReadonlySet<string>;
}

export function createLocalFacilitator(options: LocalFacilitatorOptions = {}): LocalFacilitator {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const settlementCheck = options.settlementCheck;
  const seenNonces = new Set<string>();

  const invalid = (invalidReason: string) => ({ isValid: false as const, invalidReason });

  async function verify(
    paymentPayload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<VerifyResponse> {
    if (paymentPayload.x402Version !== 2) return invalid(`unsupported x402Version ${paymentPayload.x402Version}`);
    const inner = paymentPayload.payload as Partial<EvmExactPayload>;
    const auth = inner.authorization;
    const signature = inner.signature;
    if (!auth || typeof signature !== "string") return invalid("payment payload is not an EIP-3009 authorization");

    // amount + recipient
    let value: bigint;
    try {
      value = BigInt(auth.value);
    } catch {
      return invalid("authorization.value is not an integer");
    }
    if (value < BigInt(requirements.amount)) return invalid("authorization.value below required amount");
    let to: `0x${string}`;
    let from: `0x${string}`;
    try {
      to = getAddress(auth.to);
      from = getAddress(auth.from);
    } catch {
      return invalid("authorization from/to are not addresses");
    }
    if (to !== getAddress(requirements.payTo)) return invalid("authorization.to does not match payTo");

    // validity window
    const t = now();
    const validAfter = Number(auth.validAfter);
    const validBefore = Number(auth.validBefore);
    if (!Number.isFinite(validAfter) || !Number.isFinite(validBefore)) return invalid("validity timestamps are not integers");
    if (!(validAfter <= t)) return invalid("authorization not yet valid");
    if (!(t < validBefore)) return invalid("authorization expired");

    // replay
    const nonceKey = `${from.toLowerCase()}|${auth.nonce.toLowerCase()}`;
    if (seenNonces.has(nonceKey)) return invalid("authorization nonce already used");
    if (!/^0x[0-9a-fA-F]{64}$/.test(auth.nonce)) return invalid("authorization.nonce must be a 32-byte hex");

    // EIP-712 recovery against the token domain the requirements declare
    const name = requirements.extra?.name;
    const version = requirements.extra?.version;
    if (typeof name !== "string" || typeof version !== "string") {
      return invalid("requirements.extra is missing the EIP-712 name/version");
    }
    let signer: `0x${string}`;
    try {
      signer = await recoverTypedDataAddress({
        domain: { name, version, chainId: CHAIN_ID, verifyingContract: getAddress(requirements.asset) },
        types: TRANSFER_WITH_AUTHORIZATION_TYPES,
        primaryType: "TransferWithAuthorization",
        message: {
          from,
          to,
          value,
          validAfter: BigInt(auth.validAfter),
          validBefore: BigInt(auth.validBefore),
          nonce: auth.nonce as `0x${string}`,
        },
        signature: signature as `0x${string}`,
      });
    } catch {
      return invalid("signature recovery failed");
    }
    if (signer !== from) return invalid("signature does not match authorization.from");

    // optional read-only on-chain settled-check (EIP-3009 authorizationState)
    if (settlementCheck) {
      const onChain = await settlementCheck(from, auth.nonce);
      if (onChain.settled) {
        return invalid("authorization already executed on-chain");
      }
    }

    seenNonces.add(nonceKey); // a real facilitator guards this until on-chain state takes over
    return { isValid: true, payer: from };
  }

  return {
    seenNonces,
    verify,
    async settle(paymentPayload, requirements) {
      const auth = (paymentPayload.payload as Partial<EvmExactPayload>).authorization;
      if (auth) seenNonces.add(`${getAddress(auth.from).toLowerCase()}|${auth.nonce.toLowerCase()}`);
      return {
        success: true,
        transaction: "", // verified, NOT settled on-chain — receive-only (see header)
        network: requirements.network,
        payer: auth ? getAddress(auth.from) : undefined,
      };
    },
    async getSupported() {
      return {
        kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:8453" }],
        extensions: [],
        signers: {},
      };
    },
  };
}
