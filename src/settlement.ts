/**
 * Production wiring for payment-verification step 8: has this EIP-3009
 * authorization already been executed on-chain? USDC on Base implements
 * EIP-3009's authorizationState(address authorizer, bytes32 nonce); Circle's
 * FiatToken keys the state map by the RAW nonce (confirmed callable and
 * returning false for unknown nonces by scripts/domain-check.ts).
 *
 * Read-only eth_call with fallback across the configured public RPCs.
 * If every RPC fails we return checked:false and let the caller decide —
 * the prototype server serves anyway (fail-open, $0.01 exposure); a
 * production deployment should fail closed or delegate to a facilitator.
 */
import { createPublicClient, http, getAddress } from "viem";
import type { Authorization } from "./x402.js";
import type { OnChainCheckResult } from "./payment.js";

const ERC3009_STATE_ABI = [
  {
    name: "authorizationState",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "authorizer", type: "address" },
      { name: "nonce", type: "bytes32" },
    ],
    outputs: [{ type: "bool" }],
  },
] as const;

export function makeRpcSettlementCheck(
  rpcUrls: string[],
  usdc: `0x${string}`
): (auth: Authorization) => Promise<OnChainCheckResult> {
  const clients = rpcUrls.map((url) => createPublicClient({ transport: http(url) }));
  return async (auth) => {
    const errors: string[] = [];
    for (const client of clients) {
      try {
        const state = (await client.readContract({
          address: usdc,
          abi: ERC3009_STATE_ABI,
          functionName: "authorizationState",
          args: [getAddress(auth.from), auth.nonce as `0x${string}`],
        })) as boolean;
        return { checked: true, settled: state };
      } catch (e) {
        errors.push((e as Error).message.slice(0, 120));
      }
    }
    return { checked: false, settled: false, detail: `authorizationState unreachable: ${errors.join(" | ")}` };
  };
}
