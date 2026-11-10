/**
 * The paid product: "did transaction 0x… transfer >= X USDC (or ETH) to
 * address 0x…?" — a structured verdict read from public Base RPCs with
 * fallback (pattern from tools/base-watchdog/src/config.ts).
 *
 * Limitations, honestly:
 *  - USDC mode reads ERC-20 Transfer events from the transaction receipt —
 *    direct token transfers only, which is what payments are.
 *  - ETH mode reads the transaction's own value/to (a direct transfer);
 *    internal transfers routed through contracts are NOT visible without a
 *    trace API and are reported as not paid.
 */
import { createPublicClient, http, parseUnits } from "viem";
import { CHAIN_ID, ETH_DECIMALS, USDC, USDC_DECIMALS } from "./config.js";

export type TokenKind = "usdc" | "eth";

export interface VerdictQuery {
  txHash: `0x${string}`;
  /** Optional recipient filter; omitted = any recipient. */
  to?: `0x${string}`;
  /** Minimum amount in atomic units for paid=true. */
  minAtomic: bigint;
  token: TokenKind;
}

export interface Verdict {
  paid: boolean;
  /** Human-readable amount actually transferred (matching logs summed). */
  amount: string;
  block: number | null;
  txHash: string;
  from: string | null;
  token: TokenKind;
  verifiedAt: string;
  chain: "base";
  found: boolean;
  /** Number of matching transfers summed into `amount`. */
  matched: number;
  minRequested: string;
  to: string | null;
  reason?: string;
}

/** Narrow client interface so tests can inject fakes (viem PublicClient satisfies it). */
export interface VerdictClient {
  getChainId(): Promise<number>;
  getTransactionReceipt(args: { hash: `0x${string}` }): Promise<TransactionReceiptLike | null>;
  getTransaction(args: { hash: `0x${string}` }): Promise<TransactionLike | null>;
}

export interface TransactionReceiptLike {
  status: "success" | "reverted" | string;
  blockNumber: bigint | null;
  from: string;
  logs: Array<{
    address: string;
    topics: `0x${string}`[];
    data: `0x${string}`;
  }>;
}

export interface TransactionLike {
  from: string;
  to: string | null;
  value: bigint;
}

export const TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" as const; // keccak256(Transfer(address,address,uint256))

export function makeRpcClients(rpcUrls: string[]): VerdictClient[] {
  return rpcUrls.map((url) => createPublicClient({ transport: http(url) }) as unknown as VerdictClient);
}

export function parseAmountHuman(human: string, token: TokenKind): bigint {
  const decimals = token === "usdc" ? USDC_DECIMALS : ETH_DECIMALS;
  try {
    const v = parseUnits(human, decimals);
    if (v < 0n) throw new Error("negative");
    return v;
  } catch {
    throw new Error(`min must be a non-negative decimal amount (e.g. "0.01")`);
  }
}

function formatAtomic(raw: bigint, decimals: number): string {
  const neg = raw < 0n;
  const abs = neg ? -raw : raw;
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const frac = abs % base;
  const fracStr = frac.toString().padStart(decimals, "0").replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole.toString()}${fracStr ? "." + fracStr : ""}`;
}

function topicAddress(topic: `0x${string}`): string {
  return "0x" + topic.slice(-40);
}

async function answerFromClient(client: VerdictClient, q: VerdictQuery): Promise<Verdict> {
  if ((await client.getChainId()) !== CHAIN_ID) throw new Error("RPC is not Base mainnet");
  const decimals = q.token === "usdc" ? USDC_DECIMALS : ETH_DECIMALS;
  const verifiedAt = new Date().toISOString();
  const notFound = (reason: string): Verdict => ({
    paid: false, amount: "0", block: null, txHash: q.txHash, from: null, token: q.token,
    verifiedAt, chain: "base", found: false, matched: 0,
    minRequested: formatAtomic(q.minAtomic, decimals), to: q.to ?? null, reason,
  });

  const receipt = await client.getTransactionReceipt({ hash: q.txHash });
  if (!receipt) return notFound("transaction not found");

  if (q.token === "usdc") {
    let sum = 0n;
    let matched = 0;
    let from: string | null = null;
    for (const log of receipt.logs) {
      if (log.address.toLowerCase() !== USDC.toLowerCase()) continue;
      if (log.topics[0] !== TRANSFER_TOPIC || log.topics.length < 3) continue;
      const fromAddr = topicAddress(log.topics[1] as `0x${string}`);
      const toAddr = topicAddress(log.topics[2] as `0x${string}`);
      if (q.to && toAddr.toLowerCase() !== q.to.toLowerCase()) continue;
      const value = log.data && log.data !== "0x" ? BigInt(log.data) : 0n;
      sum += value;
      matched += 1;
      from ??= fromAddr;
    }
    return {
      paid: matched > 0 && sum >= q.minAtomic,
      amount: formatAtomic(sum, USDC_DECIMALS),
      block: receipt.blockNumber !== null ? Number(receipt.blockNumber) : null,
      txHash: q.txHash,
      from,
      token: "usdc",
      verifiedAt,
      chain: "base",
      found: true,
      matched,
      minRequested: formatAtomic(q.minAtomic, USDC_DECIMALS),
      to: q.to ?? null,
    };
  }

  // ETH mode: the transaction's own value (direct transfer only)
  const tx = await client.getTransaction({ hash: q.txHash });
  if (!tx) return notFound("transaction not found");
  const toMatch = q.to ? tx.to?.toLowerCase() === q.to.toLowerCase() : tx.to !== null;
  const ok = receipt.status === "success" && toMatch && tx.value >= q.minAtomic;
  return {
    paid: ok,
    amount: formatAtomic(tx.value, ETH_DECIMALS),
    block: receipt.blockNumber !== null ? Number(receipt.blockNumber) : null,
    txHash: q.txHash,
    from: tx.from,
    token: "eth",
    verifiedAt,
    chain: "base",
    found: true,
    matched: tx.to !== null && toMatch ? 1 : 0,
    minRequested: formatAtomic(q.minAtomic, ETH_DECIMALS),
    to: tx.to ?? q.to ?? null,
    reason: receipt.status !== "success" ? "transaction reverted" : undefined,
  };
}

/** Try each client in order; first definitive answer wins (watchdog pattern). */
export async function checkPayment(clients: VerdictClient[], q: VerdictQuery): Promise<Verdict> {
  const errors: string[] = [];
  for (const client of clients) {
    try {
      return await answerFromClient(client, q);
    } catch (e) {
      errors.push((e as Error).message.slice(0, 160));
    }
  }
  throw new Error(`all RPCs failed: ${errors.join(" | ")}`);
}
