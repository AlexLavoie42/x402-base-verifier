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
 *   GET  /scan        bare GET answers the same 402 payment challenge as
 *                     /verify (GET-preflight indexable by bazaar crawlers —
 *                     a POST-only route 404s to them and is invisible); a
 *                     PAID GET without a JSON body gets a clear 400.
 *   POST /scan        PAID (100000 atomic USDC = $1.00, SCAN_PRICE_ATOMIC) —
 *                     Solidity pre-audit scanner. JSON body
 *                     { sources: { "contracts/Foo.sol": "pragma ..." },
 *                       solcVersion?: "0.8.24" } up to ~200 KB of source;
 *                     oversized/malformed bodies are rejected with a free 400
 *                     before payment is demanded. Engine: src/scanner.ts +
 *                     src/rules.ts (28 deterministic pattern rules, offline).
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
  SCAN_JSON_LIMIT,
  SCAN_MAX_SOURCE_BYTES,
  SCAN_PATH,
  SCAN_SERVICE_DESCRIPTION,
  SCAN_SERVICE_NAME,
  SCAN_SERVICE_TAGS,
  SERVICE_DESCRIPTION,
  SERVICE_NAME,
  SERVICE_TAGS,
  USDC,
  type EndpointConfig,
} from "./config.js";
import { makeRpcClients, parseAmountHuman, checkPayment, type TokenKind, type VerdictClient } from "./verdict.js";
import { EIP712_NAME, EIP712_VERSION } from "./x402.js";
import { scanSources, validateScanRequest } from "./scanner.js";

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
    scan: {
      path: SCAN_PATH,
      method: "POST (bare GET returns the 402 challenge)",
      price: `${cfg.scanPriceAtomic} atomic USDC per /scan call`,
      input: { sources: { "contracts/MyToken.sol": "pragma solidity 0.8.24; ..." }, solcVersion: "optional, e.g. 0.8.24" },
      maxSourceBytes: SCAN_MAX_SOURCE_BYTES,
      rules: "28 deterministic pattern rules; offline; severity+confidence+line per finding",
    },
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

/** Example scan output (real shape; one representative finding) for the bazaar declaration. */
const SCAN_OUTPUT_EXAMPLE = {
  findings: [
    {
      rule: "reentrancy-state-after-external-call",
      severity: "high",
      confidence: 0.6,
      file: "contracts/Vault.sol",
      line: 12,
      snippet: '(bool sent, ) = msg.sender.call{value: amount}("");',
      why: "A value-carrying external call (transfer/call{value:}/send) happens BEFORE storage is updated: the callee can re-enter and replay the not-yet-updated state (checks-effects-interactions violation).",
      fix: "Reorder to checks -> effects -> interactions (write state first, transfer last) and/or apply a nonReentrant guard.",
    },
  ],
  stats: { files: 1, lines: 30, rules_run: 28, duration_ms: 3 },
  disclaimer: "automated pattern scan; not a substitute for a professional audit",
};

const SCAN_INPUT_SCHEMA = {
  properties: {
    sources: {
      type: "object",
      description: "Map of file path -> Solidity source text (max ~200 KB of source total)",
      additionalProperties: { type: "string" },
    },
    solcVersion: { type: "string", description: 'Optional compiler version hint, e.g. "0.8.24"' },
  },
  required: ["sources"],
};

const SCAN_INPUT_EXAMPLE = {
  sources: {
    "contracts/Vault.sol":
      "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\ncontract Vault {\n    mapping(address => uint256) public balances;\n\n    function withdraw(uint256 amount) external {\n        require(balances[msg.sender] >= amount, \"insufficient\");\n        (bool sent, ) = msg.sender.call{value: amount}(\"\");\n        balances[msg.sender] -= amount;\n    }\n}\n",
  },
  solcVersion: "0.8.24",
};

/** x402 v2 route config for /scan (payment option + bazaar discovery declaration). */
function scanRouteConfig(cfg: EndpointConfig, method: "GET" | "POST") {
  return {
    accepts: {
      scheme: "exact" as const,
      // 100000 atomic USDC = $1.00: deeper per-request work than the $0.01 verify.
      price: {
        amount: cfg.scanPriceAtomic.toString(),
        asset: USDC,
        extra: { name: EIP712_NAME, version: EIP712_VERSION },
      },
      network: NETWORK_CAIP,
      payTo: cfg.payTo,
      maxTimeoutSeconds: cfg.maxTimeoutSeconds,
    },
    resource: `${cfg.baseUrl}${SCAN_PATH}`,
    description: SCAN_SERVICE_DESCRIPTION,
    mimeType: "application/json",
    serviceName: SCAN_SERVICE_NAME,
    tags: SCAN_SERVICE_TAGS,
    extensions: {
      ...declareDiscoveryExtension(
        method === "GET"
          ? {
              // GET: the bazaar/validator preflight probe — challenge only; the
              // scan input itself only ever travels as a POST JSON body
              input: SCAN_INPUT_EXAMPLE,
              inputSchema: SCAN_INPUT_SCHEMA,
              output: { example: SCAN_OUTPUT_EXAMPLE },
            }
          : {
              // POST: parameters travel as a JSON body
              bodyType: "json" as const,
              input: SCAN_INPUT_EXAMPLE,
              inputSchema: SCAN_INPUT_SCHEMA,
              output: { example: SCAN_OUTPUT_EXAMPLE },
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

  // 2. JSON body parsing regardless of content-type header (the v1 server
  //    JSON-parsed the raw body whatever the header said; parse failures ->
  //    JSON 400 "POST body must be JSON" via the error handler). /scan gets a
  //    larger limit: its sources can carry ~200 KB of Solidity (the raw-text
  //    cap is enforced by validateScanRequest; this only bounds the envelope).
  const jsonVerify = express.json({ limit: "64kb", type: () => true });
  const jsonScan = express.json({ limit: SCAN_JSON_LIMIT, type: () => true });
  app.use((req: Request, res: Response, next: NextFunction) => {
    const parser = req.path.replace(/\/+$/, "") === SCAN_PATH ? jsonScan : jsonVerify;
    parser(req, res, next);
  });

  // 3. Free param validation BEFORE the payment gate (same semantics as v1):
  //    bare request (no arguments) -> next() -> 402 challenge from the middleware;
  //    invalid params WITH arguments -> 400 for free, payment never demanded.
  //    POST /scan validates the same way: malformed/oversized sources fail
  //    free with a 400; a well-formed body falls through to the 402 gate.
  //    GET /scan skips straight to the payment gate so the bare-probe 402
  //    challenge answers bazaar/validator GET preflights (POST-only routes
  //    404 to them and are invisible); other methods 404 as before.
  app.use((req: Request, res: Response, next: NextFunction) => {
    const path = req.path.replace(/\/+$/, "");
    if (path === SCAN_PATH) {
      if (req.method !== "POST") return next(); // GET -> 402 gate; anything else 404s
      const problem = validateScanRequest(req.body);
      if (problem) return sendJson(res, 400, { error: problem });
      return next();
    }
    if (path !== RESOURCE_PATH) return next();
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
        "GET /scan": scanRouteConfig(cfg, "GET"),
        "POST /scan": scanRouteConfig(cfg, "POST"),
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

  // 6b. Paid route: the Solidity pre-audit scan (only reached with a verified
  //     payment). POST runs the scan; GET is the paid-bare-probe guard — a
  //     verified payment with no JSON body gets a clear 400 (the middleware
  //     then cancels settlement), mirroring /verify's paid-no-params 400.
  const scanHandler = (req: Request, res: Response): void => {
    const problem = validateScanRequest(req.body);
    if (problem) return sendJson(res, 400, { error: problem }); // middleware cancels settlement on 4xx
    const report = scanSources(req.body as { sources: Record<string, string> });
    log(`served scan files=${report.stats.files} findings=${report.findings.length} in ${report.stats.duration_ms}ms`);
    sendJson(res, 200, report);
  };
  app.post(SCAN_PATH, scanHandler);
  app.get(SCAN_PATH, scanHandler);

  // 7. 404 + JSON error handler (body-parse failures etc. stay JSON, like v1)
  app.use((_req: Request, res: Response) => {
    sendJson(res, 404, { error: "not found", routes: ["/", "/health", RESOURCE_PATH, `${SCAN_PATH} (GET probe → 402, POST to scan)`] });
  });
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const tooLarge =
      err instanceof Error && ((err as Error & { type?: string }).type === "entity.too.large" || /too large/i.test(err.message));
    const msg = tooLarge
      ? `request body too large (JSON envelope limit ${SCAN_JSON_LIMIT}; /scan accepts at most ${SCAN_MAX_SOURCE_BYTES} source bytes)`
      : err instanceof Error && /json|body/i.test(err.message)
        ? "POST body must be JSON"
        : "internal server error";
    if (!res.headersSent) sendJson(res, 400, { error: msg });
  });

  return app;
}
