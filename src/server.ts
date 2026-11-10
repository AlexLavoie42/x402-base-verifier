/**
 * node:http server — no framework. Routes:
 *
 *   GET  /            free service descriptor (what it does, price, example)
 *   GET  /health      liveness
 *   GET  /verify      PAID — 402 + x402 challenge unless a valid X-PAYMENT
 *                     header is attached; then a structured payment verdict.
 *                     Query: tx=0x… (required), to=0x… (optional),
 *                            min=0.01 (optional, default 0), token=usdc|eth
 *   POST /verify      same, parameters as a JSON body
 *
 * Error mapping per the x402 HTTP transport spec:
 *   malformed payment payload -> 400, payment failed -> 402 (+ accepts),
 *   success -> 200 + X-PAYMENT-RESPONSE settlement header.
 *
 * Prototype note: the server VERIFIES payments but does NOT settle them —
 * no facilitator is wired, so X-PAYMENT-RESPONSE.transaction is "" and the
 * signed authorization is left unclaimed (it expires at validBefore,
 * maxTimeoutSeconds after signing). See README for the production path.
 */
import * as http from "node:http";
import { NETWORK, RESOURCE_PATH, USDC_DECIMALS, type EndpointConfig } from "./config.js";
import { buildChallenge, buildRequirements, encodeSettlementResponse } from "./x402.js";
import { createReplayCache, verifyPayment, type VerifyPaymentDeps } from "./payment.js";
import { makeRpcClients, parseAmountHuman, checkPayment, type TokenKind, type VerdictClient } from "./verdict.js";

export interface ServerDeps {
  config: EndpointConfig;
  clients: VerdictClient[];
  paymentDeps?: VerifyPaymentDeps;
  log?: (msg: string) => void;
}

const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;

interface ParsedQuery {
  txHash: `0x${string}`;
  to?: `0x${string}`;
  minAtomic: bigint;
  token: TokenKind;
}

function parseQuery(params: URLSearchParams): { ok: true; q: ParsedQuery } | { ok: false; error: string } {
  const tx = params.get("tx");
  if (!tx) return { ok: false, error: "missing required query parameter: tx (0x… 32-byte transaction hash)" };
  if (!TX_HASH_RE.test(tx)) return { ok: false, error: "tx must be a 0x… 32-byte transaction hash" };
  const to = params.get("to");
  if (to !== null && !ADDR_RE.test(to)) return { ok: false, error: "to must be a 0x… 20-byte address" };
  const tokenParam = (params.get("token") ?? "usdc").toLowerCase();
  if (tokenParam !== "usdc" && tokenParam !== "eth") return { ok: false, error: "token must be 'usdc' or 'eth'" };
  const token = tokenParam as TokenKind;
  let minAtomic = 0n;
  const min = params.get("min");
  if (min !== null) {
    try {
      minAtomic = parseAmountHuman(min, token);
    } catch (e) {
      return { ok: false, error: (e as Error).message };
    }
  }
  return { ok: true, q: { txHash: tx as `0x${string}`, to: (to ?? undefined) as `0x${string}` | undefined, minAtomic, token } };
}

function send(res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(json),
    "access-control-allow-origin": "*",
    ...headers,
  });
  res.end(json);
}

function serviceDescriptor(cfg: EndpointConfig) {
  return {
    service: "base-payment-verification",
    price: `${cfg.priceAtomic} atomic USDC (${formatAtomicLocal(cfg.priceAtomic, USDC_DECIMALS)} USDC) per /verify call`,
    chain: "base (eip155:8453)",
    payTo: cfg.payTo,
    example: `${cfg.baseUrl}${RESOURCE_PATH}?tx=0x<txhash>&to=0x<address>&min=0.01&token=usdc`,
    howToPay: "GET /verify without payment returns HTTP 402 with an x402 challenge; retry with an X-PAYMENT header",
    verdictShape: { paid: "boolean", amount: "string", block: "number|null", txHash: "string", from: "string|null", token: "usdc|eth", verifiedAt: "ISO-8601" },
  };
}

function formatAtomicLocal(raw: bigint, decimals: number): string {
  const base = 10n ** BigInt(decimals);
  const whole = raw / base;
  const frac = (raw % base).toString().padStart(decimals, "0").replace(/0+$/, "");
  return `${whole.toString()}${frac ? "." + frac : ""}`;
}

async function readBodyJson(req: http.IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString("utf-8");
  if (!raw.trim()) return new URLSearchParams();
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(parsed)) if (v !== null && typeof v !== "object") params.set(k, String(v));
  return params;
}

export function createApp(deps: ServerDeps): http.Server {
  const { config: cfg, clients } = deps;
  const log = deps.log ?? (() => {});
  const replayCache = deps.paymentDeps?.replayCache ?? createReplayCache();
  const paymentDeps: VerifyPaymentDeps = { ...deps.paymentDeps, replayCache };

  return http.createServer((req, res) => {
    void handle(req, res).catch((e) => {
      log(`error: ${(e as Error).message}`);
      if (!res.headersSent) send(res, 500, { x402Version: 1, error: "internal server error" });
      else res.end();
    });

    async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      const path = url.pathname.replace(/\/+$/, "") || "/";

      if (req.method === "GET" && path === "/") return send(res, 200, serviceDescriptor(cfg));
      if (req.method === "GET" && path === "/health") return send(res, 200, { ok: true });

      if ((req.method === "GET" || req.method === "POST") && path === RESOURCE_PATH) {
        // 1. Validate the request itself (free — don't take payment for garbage)
        let params: URLSearchParams;
        if (req.method === "POST") {
          try {
            params = await readBodyJson(req);
          } catch {
            return send(res, 400, { x402Version: 1, error: "POST body must be JSON" });
          }
        } else {
          params = url.searchParams;
        }
        const parsed = parseQuery(params);
        // x402/Bazaar preflight convention: a bare GET (no query params) gets the 402
        // challenge, not a param error — validators and agent probes expect payment
        // gating to come first. Malformed params WITH arguments still fail free.
        const isBareProbe = req.method === "GET" && url.searchParams.toString() === "";
        if (!parsed.ok && !isBareProbe) return send(res, 400, { x402Version: 1, error: parsed.error });

        // 2. Payment gate
        const resource = `${cfg.baseUrl}${RESOURCE_PATH}`;
        const reqs = buildRequirements(cfg, resource);
        const challenge = buildChallenge(cfg, resource);
        const header = req.headers["x-payment"];
        if (typeof header !== "string" || header.length === 0) {
          return send(res, 402, challenge);
        }
        const verification = await verifyPayment(header, reqs, paymentDeps);
        if (!verification.isValid) {
          if (verification.malformed) {
            return send(res, 400, { x402Version: 1, error: verification.invalidReason, accepts: challenge.accepts });
          }
          log(`payment rejected: ${verification.invalidReason}`);
          const claimedFrom = verification.payload?.payload.authorization.from ?? "";
          return send(res, 402, challenge, {
            "x-payment-response": encodeSettlementResponse({
              success: false,
              errorReason: verification.invalidReason,
              transaction: "",
              network: NETWORK,
              payer: ADDR_RE.test(claimedFrom) ? claimedFrom : "",
            }),
          });
        }

        // 3. Paid work: the verdict (guard: a paid bare probe without params)
        if (!parsed.ok) {
          return send(res, 400, {
            x402Version: 1,
            error: `payment verified but request params invalid: ${parsed.error}. Required query: tx=0x…, to=0x…, min=<decimal>, token=usdc|eth`,
          });
        }
        let verdict;
        try {
          verdict = await checkPayment(clients, parsed.q);
        } catch (e) {
          // could not answer — be honest, don't keep the money silently
          log(`rpc failure after payment: ${(e as Error).message}`);
          return send(res, 502, {
            x402Version: 1,
            error: "upstream Base RPCs unavailable; payment was verified but no verdict could be produced — retry with the same X-PAYMENT header within its validity window",
          });
        }
        log(`served verdict paid=${verdict.paid} tx=${verdict.txHash} payer=${verification.payer}`);
        return send(res, 200, verdict, {
          "x-payment-response": encodeSettlementResponse({
            success: true,
            transaction: "", // prototype verifies but does not settle (README)
            network: NETWORK,
            payer: verification.payer ?? "",
          }),
        });
      }

      return send(res, 404, { error: "not found", routes: ["/", "/health", RESOURCE_PATH] });
    }
  });
}
