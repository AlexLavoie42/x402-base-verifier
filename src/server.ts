/**
 * Express server wired through the OFFICIAL x402 v2 payment middleware
 * (@x402/express + @x402/core + @x402/evm + @x402/extensions).
 *
 * Routes:
 *   GET  /            free service descriptor (what it does, price, example)
 *   GET  /health      liveness
 *   GET  /verify      PAID — official middleware emits the v2 402 challenge
 *                     (PaymentRequired in the PAYMENT-REQUIRED response
 *                     header, x402Version 2) unless a valid PAYMENT-SIGNATURE
 *                     header is attached; then a structured payment verdict.
 *                     Query: tx=0x… (required), to=0x… (optional),
 *                            min=0.01 (optional, default 0), token=usdc|eth
 *   POST /verify      same, parameters as a JSON body
 *
 * Verification path: facilitator-based, exactly as the SDK intends — the
 * middleware asks the configured facilitator (default Coinbase's hosted
 * https://x402.org/facilitator) to verify the EIP-3009 payment before the
 * handler runs and to settle it after a 2xx. The server itself signs and
 * sends NOTHING (receive-only operation); the facilitator does the on-chain
 * work for a fee.
 *
 * Param-validation semantics (unchanged from the v1 server): a bare GET/POST
 * (no arguments) passes straight through to the payment gate and gets the
 * 402 challenge; arguments that are present but invalid fail free with a
 * 400 BEFORE payment is demanded; a paid request with missing/invalid params
 * gets a 400 after verification (the middleware then cancels settlement).
 *
 * Bazaar discovery: the /verify routes declare the bazaar extension
 * (input schema + output example) so x402 discovery indexers can catalog it.
 */
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import type { FacilitatorClient } from "@x402/core/server";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import {
  NETWORK_CAIP,
  RESOURCE_PATH,
  SERVICE_DESCRIPTION,
  SERVICE_NAME,
  SERVICE_TAGS,
  USDC,
  type EndpointConfig,
} from "./config.js";
import { makeRpcClients, parseAmountHuman, checkPayment, type TokenKind, type VerdictClient } from "./verdict.js";
import { EIP712_NAME, EIP712_VERSION } from "./x402.js";

export interface ServerDeps {
  config: EndpointConfig;
  clients: VerdictClient[];
  /**
   * The facilitator the middleware's standard verification path talks to.
   * Wired by the entry point: the in-process verify-only facilitator by
   * default (receive-only operation), or an HTTPFacilitatorClient when
   * FACILITATOR_URL names one that supports Base mainnet.
   */
  facilitator: FacilitatorClient;
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

function sendJson(res: Response, status: number, body: unknown): void {
  res.status(status).json(body);
}

function serviceDescriptor(cfg: EndpointConfig) {
  return {
    service: SERVICE_NAME,
    x402Version: 2,
    price: `${cfg.priceAtomic} atomic USDC per /verify call`,
    chain: "base (eip155:8453)",
    asset: USDC,
    payTo: cfg.payTo,
    facilitator: cfg.facilitatorUrl ?? "in-process verify-only facilitator (verified, not settled on-chain)",
    example: `${cfg.baseUrl}${RESOURCE_PATH}?tx=0x<txhash>&to=0x<address>&min=0.01&token=usdc`,
    howToPay: "GET /verify without payment returns HTTP 402 with a PAYMENT-REQUIRED header (base64 PaymentRequired, x402Version 2); retry with a PAYMENT-SIGNATURE header",
    verdictShape: { paid: "boolean", amount: "string", block: "number|null", txHash: "string", from: "string|null", token: "usdc|eth", verifiedAt: "ISO-8601" },
  };
}

/** Example verdict (real output shape) for the bazaar discovery declaration. */
const VERDICT_EXAMPLE = {
  paid: true,
  amount: "11.81",
  block: 55749678,
  txHash: "0x7153acfd79cd3c7119f096807be6307ba9ef9fab72d505cfa9437806dcd973c9",
  from: "0xff9592258b601e0592570295894ba19b505c0257",
  token: "usdc",
  verifiedAt: "2026-11-10T19:51:55.295Z",
  chain: "base",
  found: true,
  matched: 1,
  minRequested: "0.01",
  to: "0x870435Ee7bD072bCeD4Ef74b405D7C8a436ea973",
};

/** Shared input schema for /verify parameters (query for GET, JSON body for POST). */
const VERIFY_INPUT_SCHEMA = {
  properties: {
    tx: { type: "string", description: "Base transaction hash to verify (0x… 32 bytes)" },
    to: { type: "string", description: "Optional recipient filter (0x… 20-byte address)" },
    min: { type: "string", description: "Optional minimum amount as a decimal string, e.g. \"0.01\" (default 0)" },
    token: { type: "string", enum: ["usdc", "eth"], description: "Token kind to check (default usdc)" },
  },
  required: ["tx"],
};

const VERIFY_INPUT_EXAMPLE = {
  tx: "0x7153acfd79cd3c7119f096807be6307ba9ef9fab72d505cfa9437806dcd973c9",
  to: "0x870435Ee7bD072bCeD4Ef74b405D7C8a436ea973",
  min: "0.01",
  token: "usdc",
};

/** x402 v2 route config for /verify (payment option + bazaar discovery declaration). */
function verifyRouteConfig(cfg: EndpointConfig, method: "GET" | "POST") {
  return {
    accepts: {
      scheme: "exact" as const,
      // Explicit AssetAmount: 10000 atomic USDC = $0.01, pinned to the native
      // USDC contract + its EIP-3009 signing domain (extra.name/version).
      price: {
        amount: cfg.priceAtomic.toString(),
        asset: USDC,
        extra: { name: EIP712_NAME, version: EIP712_VERSION },
      },
      network: NETWORK_CAIP,
      payTo: cfg.payTo,
      maxTimeoutSeconds: cfg.maxTimeoutSeconds,
    },
    resource: `${cfg.baseUrl}${RESOURCE_PATH}`,
    description: SERVICE_DESCRIPTION,
    mimeType: "application/json",
    serviceName: SERVICE_NAME,
    tags: SERVICE_TAGS,
    extensions: {
      ...declareDiscoveryExtension(
        method === "GET"
          ? {
              // GET: parameters travel as query params
              input: VERIFY_INPUT_EXAMPLE,
              inputSchema: VERIFY_INPUT_SCHEMA,
              output: { example: VERDICT_EXAMPLE },
            }
          : {
              // POST: parameters travel as a JSON body
              bodyType: "json" as const,
              input: VERIFY_INPUT_EXAMPLE,
              inputSchema: VERIFY_INPUT_SCHEMA,
              output: { example: VERDICT_EXAMPLE },
            },
      ),
    },
  };
}

/**
 * Request params as URLSearchParams; null when the request is a "bare probe"
 * (GET/HEAD with no query string) that should fall through to the 402 gate.
 * POST is always validated (an empty body is a 400, as in the v1 server).
 */
function requestParams(req: Request): URLSearchParams | null {
  if (req.method === "GET" || req.method === "HEAD") {
    const qs = new URL(req.originalUrl, "http://x").searchParams;
    return qs.toString() === "" ? null : qs;
  }
  const body = req.body;
  if (body === undefined || body === null) return new URLSearchParams();
  if (typeof body !== "object" || Array.isArray(body)) return new URLSearchParams(); // present but wrong shape -> 400
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(body as Record<string, unknown>)) {
    if (v !== null && typeof v !== "object") params.set(k, String(v));
  }
  return params;
}

export function createApp(deps: ServerDeps): Express {
  const { config: cfg, clients, facilitator } = deps;
  const log = deps.log ?? (() => {});

  const app = express();
  app.disable("x-powered-by");

  // 1. CORS on everything (kept from the v1 node:http server)
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, PAYMENT-SIGNATURE, X-PAYMENT");
    if (req.method === "OPTIONS") {
      res.status(204).end();
      return;
    }
    next();
  });

  // 2. JSON body parsing for POST /verify, regardless of content-type header
  //    (the v1 server JSON-parsed the raw body whatever the header said;
  //    parse failures -> JSON 400 "POST body must be JSON" via the error handler)
  app.use(express.json({ limit: "64kb", type: () => true }));

  // 3. Free param validation BEFORE the payment gate (same semantics as v1):
  //    bare request (no arguments) -> next() -> 402 challenge from the middleware;
  //    invalid params WITH arguments -> 400 for free, payment never demanded.
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.replace(/\/+$/, "") !== RESOURCE_PATH) return next();
    const params = requestParams(req);
    if (params === null) return next(); // bare probe: let the middleware charge the gate
    const parsed = parseQuery(params);
    if (!parsed.ok) return sendJson(res, 400, { error: parsed.error });
    next();
  });

  // 4. The official x402 v2 payment middleware (402 + PAYMENT-REQUIRED header,
  //    facilitator verify before the handler, facilitator settle after 2xx).
  app.use(
    paymentMiddleware(
      {
        "GET /verify": verifyRouteConfig(cfg, "GET"),
        "POST /verify": verifyRouteConfig(cfg, "POST"),
      },
      new x402ResourceServer(facilitator).register(NETWORK_CAIP, new ExactEvmScheme()),
    ),
  );

  // 5. Free routes
  app.get("/", (_req: Request, res: Response) => sendJson(res, 200, serviceDescriptor(cfg)));
  app.get("/health", (_req: Request, res: Response) => sendJson(res, 200, { ok: true }));

  // 6. Paid route: the verdict (only reached with a verified payment)
  const verdictHandler = async (req: Request, res: Response): Promise<void> => {
    const params = requestParams(req);
    const parsed = params ? parseQuery(params) : null;
    if (!parsed || !parsed.ok) {
      return sendJson(res, 400, {
        error:
          "payment verified but request params invalid: tx (0x… 32-byte hash) is required; optional: to (0x… address), min (decimal), token (usdc|eth)",
      });
    }
    let verdict;
    try {
      verdict = await checkPayment(clients, parsed.q);
    } catch (e) {
      // could not answer — be honest; the middleware cancels settlement on >= 400
      log(`rpc failure after payment: ${(e as Error).message}`);
      return sendJson(res, 502, {
        error: "upstream Base RPCs unavailable; payment was not settled — retry within the payment validity window",
      });
    }
    log(`served verdict paid=${verdict.paid} tx=${verdict.txHash}`);
    sendJson(res, 200, verdict);
  };
  app.get(RESOURCE_PATH, verdictHandler);
  app.post(RESOURCE_PATH, verdictHandler);

  // 7. 404 + JSON error handler (body-parse failures etc. stay JSON, like v1)
  app.use((_req: Request, res: Response) => {
    sendJson(res, 404, { error: "not found", routes: ["/", "/health", RESOURCE_PATH] });
  });
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const msg = err instanceof Error && /json|body/i.test(err.message) ? "POST body must be JSON" : "internal server error";
    if (!res.headersSent) sendJson(res, 400, { error: msg });
  });

  return app;
}
