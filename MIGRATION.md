# MIGRATION.md — hand-rolled x402 v1 → OFFICIAL x402 v2 SDK

Date: 2026-11-10. Goal: pass agentic.market's validator, which was failing
ONLY on: *"x402 version is 2 — endpoint uses x402 v1; PaymentRequired
delivered in PAYMENT-REQUIRED header"*.

## What changed

**New dependencies** (`package.json`): `@x402/express`, `@x402/core`,
`@x402/evm`, `@x402/extensions` (all 2.30.0 — the official x402 Foundation
SDK, https://github.com/x402-foundation/x402), plus `express` 5 +
`@types/express` (the official middleware is express-based). `engines.node`
bumped `>=20` → `>=22` (SDK monorepo requirement).

**`src/server.ts`** — rewritten. `node:http` routing → express app with the
official `paymentMiddleware` from `@x402/express` protecting `GET /verify` and
`POST /verify`:

- 402 challenge is now the v2 wire shape the validator wants:
  `x402Version: 2`, full `PaymentRequired` (resource metadata + `accepts`)
  base64-encoded in the **`PAYMENT-REQUIRED` response header** (body stays
  JSON `{error}`). Payments arrive via **`PAYMENT-SIGNATURE`** (v2 client
  header); receipts return via **`PAYMENT-RESPONSE`**.
- Payment option: scheme `exact`, network `eip155:8453`, price
  `{ amount: "10000", asset: 0x8335…2913 (native USDC), extra: { name:
  "USD Coin", version: "2" } }` (= $0.01, pinned explicitly rather than via
  the SDK's `$`-money default-asset lookup), `payTo
  0x696344061b0f4CcFbA0b48a8390330C6b2525531`, `maxTimeoutSeconds` 30.
- **Bazaar discovery extension** declared on both routes
  (`declareDiscoveryExtension` from `@x402/extensions/bazaar`): query/body
  input schema (tx required; to/min/token optional) + real output example;
  also `serviceName`/`tags` in the resource metadata. The challenge's
  `extensions.bazaar` rides along in every 402 for discovery indexers.
- **Facilitator-based verify via the middleware's standard path** (requirement:
  the server verifies, never signs). `x402ResourceServer(facilitator)
  .register("eip155:8453", new ExactEvmScheme())`.
- Kept: `/health`, `/` free descriptor (now x402Version 2), the verdict logic
  (`src/verdict.ts` untouched — RPC fallback included), CORS on every
  response, and the param-validation semantics — a small pre-middleware
  returns 400 for *invalid params WITH arguments* before the payment gate;
  bare GET/POST (no args) falls through to the middleware and gets the 402
  challenge; a paid request with bad params 400s after verification and the
  middleware cancels settlement; verdict-RPC failure → honest 502 with
  settlement cancelled (verified live: fake tx hash → 502, nothing settled).

**Facilitator choice — the one real design decision.** Coinbase's hosted
facilitator (`https://x402.org/facilitator`, the SDK default) does **NOT
support Base mainnet** (`eip155:8453`) as of 2026-11 — probed live: its
`/supported` lists only `eip155:84532` (Base Sepolia) + non-EVM chains.
Wiring it (the previous plan of record) makes every request fail at startup
validation (`RouteConfigurationError: Facilitator does not support scheme
"exact" on network "eip155:8453"` — reproduced). The official
self-facilitation example needs a signing wallet (prohibited: receive-only).
So:

- **Default (this deploy): in-process verify-only facilitator**
  (`src/local-facilitator.ts`, a standard `FacilitatorClient` handed to the
  middleware). `verify()` does the full off-chain EIP-3009 validation the old
  hand-rolled gate did — EIP-712 recovery against the USDC-on-Base domain
  (binds signature to the token), payTo/amount/validity-window checks, nonce
  replay guard — **plus** a read-only on-chain
  `USDC.authorizationState(from, nonce)` check over the public RPC fallback
  list (`src/settlement.ts`, now keyed `(from, nonce)`; this wires the old
  README production item "wire check 8"). `settle()` burns the nonce and
  returns `success: true, transaction: ""` — **nothing is ever signed, sent,
  or broadcast by this process**; the signed authorization simply expires
  unclaimed at `validBefore`, and `tools/base-watchdog` remains the
  settlement observer for USDC actually arriving at payTo. Same posture as
  the v1 prototype (verified-not-settled), now behind the official
  middleware.
- **Opt-in hosted facilitator:** set `FACILITATOR_URL` (env) and the entry
  point wires `HTTPFacilitatorClient` against it instead — the right switch
  when a facilitator that actually covers Base mainnet exists (e.g. Coinbase
  Developer Platform's, which needs an operator-created API key wired via
  `createAuthHeaders`). It must advertise v2 `exact` on `eip155:8453` or the
  middleware rejects all traffic (fail-closed, loudly).

**Other files:** `src/config.ts` — added `NETWORK_CAIP`, `FACILITATOR_URL`
(null default = local facilitator), `SERVICE_NAME`/`SERVICE_TAGS`;
`src/payment.ts` (v1 EIP-3009 manual verifier) and `src/x402.ts` (v1 wire
types + EIP-712 helpers) **kept as library exports** — the middleware path is
authoritative, the old module is no longer in the request path;
`src/local-facilitator.ts` new; `scripts/smoke.ts` rewritten for the v2
challenge/PAYMENT-SIGNATURE flow (local facilitator + live Base RPCs —
verified working against live block data); `render.yaml` synced to the
publish mirror's build (`npm ci --include=dev && npx tsc -p tsconfig.json`,
`node dist/src/server-main.js`); README banner points here.

**Tests:** `test/payment.test.ts` (13, v1 library — unchanged) and
`test/verdict.test.ts` (7, unchanged) stay; `test/server.test.ts` rewritten
for v2 (14 tests): challenge-in-PAYMENT-REQUIRED-header shape, full
402→sign→200 flow with `PAYMENT-RESPONSE` receipt, replay rejection, verify
failures, free-param-400 semantics, bare-GET-402, POST gate, CORS, 404. All
offline — the facilitator is mocked by injecting the local facilitator (it
performs real local signature recovery, no network, no settlement).
**34/34 pass; `npx tsc --noEmit` clean.** The compiled-JS deploy path
(`tsc` → `node dist/src/server-main.js`) was booted and verified end-to-end
against live Base data: 402 v2 challenge, paid 200 verdict + receipt, replay
402, read-only authorizationState check included.

## Exact deploy steps (orchestrator)

1. Local gate (already green, re-run to be sure):
   `cd tools/x402-endpoint && npm test && npx tsc --noEmit`
2. Sync the package into the publish mirror (same file set as before):
   `src/ test/ scripts/ package.json package-lock.json tsconfig.json
   render.yaml README.md MIGRATION.md LICENSE RENDER-DEPLOY.md` →
   `C:\Users\lavoi\Money\.scratch\publish\x402` (replace `src`, `test`,
   `scripts`; do NOT copy `dist/` or `node_modules/`). Commit there.
3. `git push` from `.scratch\publish\x402` (origin
   `https://github.com/AlexLavoie42/x402-base-verifier.git`) — orchestrator
   action.
4. Render: manual deploy of service `srv-dbppa00ae00c73c7fqeg`
   (x402-verifier.onrender.com). Env on Render must include
   `BASE_URL=https://x402-verifier.onrender.com` (the challenge's
   `resource.url` comes from it). `NODE_ENV=production` already set; leave
   `FACILITATOR_URL` unset for the in-process verify-only facilitator;
   `RPC_URLS` optional (defaults to base.drpc.org + mainnet.base.org).
5. Verify: `curl -s https://x402-verifier.onrender.com/health` →
   `{"ok":true}`; `curl -si https://x402-verifier.onrender.com/verify` → 402
   with a `PAYMENT-REQUIRED` header whose base64 payload has
   `"x402Version":2`.
6. Re-run the agentic.market validator on the listing.

## What the validator might still flag

- **Settlement posture.** `PAYMENT-RESPONSE.transaction` is `""` — payments
  are verified, not settled on-chain (receive-only charter; no facilitator
  covers Base mainnet today). If the validator ever starts checking that a
  real settlement tx hash is returned, the fix is a Base-mainnet-capable
  hosted facilitator via `FACILITATOR_URL` (operator decision — CDP needs an
  API key) — one env var, no code change.
- Cold-start timing on Render free tier is unchanged (~30 s+); the 402 path
  is fully offline under the default facilitator (no x402.org dependency).
- The replay guard is in-memory per-process (as before); Render restarts
  clear it within the ≤30 s validity window. The on-chain
  `authorizationState` check still catches reuse after settlement elsewhere.
