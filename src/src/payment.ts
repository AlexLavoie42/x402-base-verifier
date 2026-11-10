/**
 * Payment gate: verify an x402 v1 X-PAYMENT header carrying a signed
 * EIP-3009 transferWithAuthorization for USDC on Base.
 *
 * Verification order (cheap/local first, network last):
 *   1. decode + shape (400-class "malformed")
 *   2. scheme / network / x402Version match the challenge
 *   3. authorization.to === payTo
 *   4. authorization.value >= maxAmountRequired
 *   5. validAfter <= now < validBefore
 *   6. EIP-712 signature recovery against the USDC-on-Base domain
 *      ({ "USD Coin", "2", 8453, 0x8335…2913 } — confirmed live via
 *      scripts/domain-check.ts) — recovered signer must equal authorization.from.
 *      Recovering against THIS domain also binds the signature to the USDC
 *      contract: a signature made for any other token/domain won't recover.
 *   7. replay cache (in-memory, per-process; nonce unseen)
 *   8. on-chain settled-check: USDC.authorizationState(from, nonce) must be
 *      false (EIP-3009; Circle's FiatToken keys state by the raw nonce —
 *      probed live by scripts/domain-check.ts). Prototype default is a
 *      documented stub; production wires makeRpcSettlementCheck() or a
 *      facilitator.
 */
import { getAddress, recoverTypedDataAddress } from "viem";
import {
  buildTypedData,
  decodePaymentHeader,
  type Authorization,
  type PaymentPayload,
  type PaymentRequirements,
} from "./x402.js";

export interface OnChainCheckResult {
  checked: boolean;
  settled: boolean;
  detail?: string;
}

export interface VerifyPaymentDeps {
  now?: () => number; // injectable clock (tests)
  replayCache?: ReplayCache;
  settlementCheck?: (auth: Authorization) => Promise<OnChainCheckResult>;
}

export interface PaymentVerification {
  /** true only when every check passed. */
  isValid: boolean;
  /** true => 400-class transport error; false => 402-class payment failure. */
  malformed: boolean;
  payer?: `0x${string}`;
  payload?: PaymentPayload;
  invalidReason?: string;
  onChainCheck?: OnChainCheckResult;
}

/** In-memory nonce cache with TTL = validity window. Process-local: restart clears it. */
export interface ReplayCache {
  seen(auth: Authorization): boolean;
  mark(auth: Authorization): void;
}

/** Module-level default so bare verifyPayment calls still share replay state. */
const defaultReplayCache = createReplayCache();

export function createReplayCache(now: () => number = () => Math.floor(Date.now() / 1000)): ReplayCache {
  const map = new Map<string, number>(); // key -> validBefore (unix s)
  const key = (auth: Authorization) => `${auth.from.toLowerCase()}|${auth.nonce.toLowerCase()}`;
  return {
    seen(auth) {
      const k = key(auth);
      const vb = map.get(k);
      if (vb === undefined) return false;
      if (vb <= now()) {
        map.delete(k); // authorization expired; re-signing it is worthless
        return false;
      }
      return true;
    },
    mark(auth) {
      map.set(key(auth), Number(auth.validBefore));
    },
  };
}

/** Default settled-check: STUB — skips the RPC call. Documented prototype limitation. */
export const stubSettlementCheck = async (_auth: Authorization): Promise<OnChainCheckResult> => ({
  checked: false,
  settled: false,
  detail: "prototype stub: on-chain authorizationState not queried",
});

function isHex32(s: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(s);
}

export async function verifyPayment(
  header: string,
  reqs: PaymentRequirements,
  deps: VerifyPaymentDeps = {}
): Promise<PaymentVerification> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const cache = deps.replayCache ?? defaultReplayCache;
  const check = deps.settlementCheck ?? stubSettlementCheck;

  let payload: PaymentPayload;
  try {
    payload = decodePaymentHeader(header);
  } catch (e) {
    return { isValid: false, malformed: true, invalidReason: (e as Error).message };
  }

  const auth = payload.payload.authorization;
  const reject = (invalidReason: string): PaymentVerification => ({ isValid: false, malformed: false, payload, invalidReason });

  // 2. envelope must match the challenge it answers
  if (payload.x402Version !== 1) return reject(`unsupported x402Version ${payload.x402Version}`);
  if (payload.scheme !== reqs.scheme) return reject(`unsupported scheme ${payload.scheme}`);
  if (payload.network !== reqs.network) return reject(`unsupported network ${payload.network}`);

  // 3. must pay our address
  let to: string;
  try {
    to = getAddress(auth.to);
  } catch {
    return reject("authorization.to is not an address");
  }
  if (to !== getAddress(reqs.payTo)) return reject("authorization.to does not match payTo");

  // 4. amount
  let value: bigint;
  try {
    value = BigInt(auth.value);
  } catch {
    return reject("authorization.value is not an integer");
  }
  if (value < BigInt(reqs.maxAmountRequired)) return reject("authorization.value below maxAmountRequired");

  // 5. validity window
  let validAfter: number, validBefore: number;
  try {
    validAfter = Number(auth.validAfter);
    validBefore = Number(auth.validBefore);
  } catch {
    return reject("authorization validity timestamps are not integers");
  }
  const t = now();
  if (!(validAfter <= t)) return reject("authorization not yet valid");
  if (!(t < validBefore)) return reject("authorization expired");

  if (!isHex32(auth.nonce)) return reject("authorization.nonce must be a 32-byte hex");

  // 6. signature recovery against the USDC-on-Base EIP-712 domain
  let signer: `0x${string}`;
  try {
    signer = await recoverTypedDataAddress({ ...buildTypedData(auth), signature: payload.payload.signature as `0x${string}` });
  } catch {
    return reject("signature recovery failed");
  }
  let from: `0x${string}`;
  try {
    from = getAddress(auth.from);
  } catch {
    return reject("authorization.from is not an address");
  }
  if (signer !== from) return reject("signature does not match authorization.from");

  // 7. replay
  if (cache.seen(auth)) return reject("authorization nonce already used at this endpoint");

  // 8. on-chain settled state (prototype: injectable, default stub)
  const onChainCheck = await check(auth);
  if (onChainCheck.settled) {
    return reject(`authorization already executed on-chain${onChainCheck.detail ? ` (${onChainCheck.detail})` : ""}`);
  }

  cache.mark(auth);
  return { isValid: true, malformed: false, payer: from, payload, onChainCheck };
}
