# x402-endpoint — Base payment verification, $0.01 per call

> **MIGRATED to x402 v2 (official SDK).** The wire protocol below describes
> the OLD v1 implementation and is kept for background. The live endpoint now
> serves the v2 challenge (x402Version 2, PaymentRequired in the
> `PAYMENT-REQUIRED` response header, payments via `PAYMENT-SIGNATURE`,
> receipts via `PAYMENT-RESPONSE`) through the official
> `@x402/express` middleware with the Bazaar discovery extension, and verifies
> payments through the middleware's facilitator path. See **MIGRATION.md**
> for what changed, the in-process verify-only facilitator, and deploy steps.

A receive-side **x402 v1** paid endpoint (LOCAL PROTOTYPE — not deployed, not
listed). It sells one genuinely useful question:

> Did transaction `0x…` transfer ≥ X USDC (or ETH) to address `0x…`?

and answers with a structured verdict over public Base RPCs:

```json
{
  "paid": true,
  "amount": "11.81",
  "block": 55749678,
  "txHash": "0x7153acfd79cd3c7119f096807be6307ba9ef9fab72d505cfa9437806dcd973c9",
  "from": "0xff9592258b601e0592570295894ba19b505c0257",
  "token": "usdc",
  "verifiedAt": "2026-11-10T19:51:55.295Z",
  "chain": "base",
  "found": true,
  "matched": 1,
  "minRequested": "0.01",
  "to": "0x870435Ee7bD072bCeD4Ef74b405D7C8a436ea973"
}
```

(that verdict is real output from `npx tsx scripts/smoke.ts`, run against a
live Base transaction)

## Protocol behavior (x402 v1, HTTP transport, per the official spec)

1. `GET /verify?tx=0x…&to=0x…&min=0.01&token=usdc` without payment →
   **402** with a challenge body:
   ```json
   {
     "x402Version": 1,
     "error": "X-PAYMENT header is required",
     "accepts": [{
       "scheme": "exact",
       "network": "base",
       "maxAmountRequired": "10000",
       "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
       "payTo": "0x696344061b0f4CcFbA0b48a8390330C6b2525531",
       "resource": "https://<host>/verify",
       "description": "Base payment verification: …",
       "mimeType": "application/json",
       "outputSchema": null,
       "maxTimeoutSeconds": 30,
       "extra": { "name": "USD Coin", "version": "2" }
     }]
   }
   ```
2. Client signs an **EIP-3009 `transferWithAuthorization`** over the EIP-712
   domain `{ name: "USD Coin", version: "2", chainId: 8453, verifyingContract:
   0x8335…2913 }` and retries with `X-PAYMENT` (standard base64 JSON, exactly
   the shape the official `x402` TS client emits).
3. Server verifies (below) → **200** + verdict + `X-PAYMENT-RESPONSE`
   settlement header (base64 `{success, transaction, network, payer}`).

Other routes: `GET /` (free service descriptor), `GET /health` (liveness),
`POST /verify` (same params as JSON body, same payment gate). Bad query
params → 400 for free (never take payment for an unanswerable request).

## What the payment gate verifies (`src/payment.ts`)

| # | Check | Where |
|---|-------|-------|
| 1 | header decodes (base64 or base64url), right shape | local |
| 2 | `x402Version` 1, scheme `exact`, network `base` match the challenge | local |
| 3 | `authorization.to` === our `payTo` | local |
| 4 | `authorization.value` ≥ `maxAmountRequired` (10000 atomic = $0.01) | local |
| 5 | `validAfter ≤ now < validBefore` | local |
| 6 | EIP-712 signature recovers to `authorization.from` against the **USDC-on-Base domain** — recovering against that domain is also what binds the signature to the USDC contract | local |
| 7 | nonce unseen (in-memory replay cache, TTL = validity window) | local |
| 8 | `USDC.authorizationState(from, nonce) === false` (EIP-3009 state map) | **RPC — STUBBED by default in the prototype** (`src/settlement.ts` has the real read-only implementation, `makeRpcSettlementCheck`) |

The EIP-712 domain is not folklore: `npm run domain-check` compares the live
contract's `DOMAIN_SEPARATOR()` against locally computed candidates (read-only
`eth_call`), proving `"USD Coin"`/`"2"`/8453 matches and `authorizationState`
is callable. Rerun it whenever the token contract could have changed.

## Prototype honesty box (read before relying on it)

- **No settlement.** The server *verifies* the signed authorization but does
  not submit it (that needs a gas-paying facilitator account — prohibited for
  this operation). `X-PAYMENT-RESPONSE.transaction` is `""`. A signed but
  unclaimed authorization expires harmlessly at `validBefore`.
- **Check 8 is a stub by default** — wire `makeRpcSettlementCheck(rpcs, USDC)`
  into `createApp({ paymentDeps: { settlementCheck } })` for the real
  read-only check. Without it, replay of the *same* nonce at this endpoint is
  still blocked by check 7; what the stub misses is detecting an auth
  *already executed on-chain* (an auth settled elsewhere then re-submitted
  here) — a $0.01 exposure per incident.
- **Replay cache is in-memory** (per-process). Restart = amnesia within the
  ≤30 s validity window.
- **Fail-open on RPC outage for check 8; fail-closed (502) for the verdict
  itself** — if we can't produce the verdict after taking a payment we say so
  instead of silently keeping money.

## Layout

```
src/config.ts    constants + env (price, payTo, RPC fallback list + quirks)
src/x402.ts      v1 wire types, 402 challenge builder, header codecs, EIP-712 domain
src/payment.ts   the 8-step payment gate + replay cache
src/settlement.ts production read-only authorizationState checker (fallback RPCs)
src/verdict.ts   the paid product: receipt/tx -> verdict (USDC logs or ETH value)
src/server.ts    node:http wiring (no framework)
scripts/domain-check.ts  live DOMAIN_SEPARATOR proof (read-only)
scripts/smoke.ts         live end-to-end 402 -> sign -> 200 demo (read-only RPC)
```

## Run

```bash
npm install
npm test            # 27 tests, offline, ~4 s (throwaway dev keys only)
npm run typecheck
npm start           # http://localhost:3000  (env: PORT, BASE_URL, RPC_URLS, PRICE_ATOMIC, PAY_TO)
npx tsx scripts/smoke.ts   # live loop against real Base data
```

Env defaults: price 10000 atomic USDC ($0.01), payTo
`0x696344061b0f4CcFbA0b48a8390330C6b2525531` (the operation's receive-only
wallet — receiving requires no gas, no transactions, no account creation),
RPCs `https://base.drpc.org,https://mainnet.base.org` with the public-RPC
quirks documented in `tools/base-watchdog/src/config.ts` (mainnet.base.org
429s address-less `eth_getLogs`, which this endpoint never does — it only
reads receipts/transactions).

## What changes for production (go-live path)

1. **Settlement.** Pick one:
   - *Hosted facilitator*: point at Coinbase's x402 facilitator (`/verify`
     and `/settle` HTTP APIs per the spec) — it settles for a fee; no gas
     account of ours needed. Cleanest under the no-transactions charter.
   - *Self-settling watcher*: an agent-side process submits
     `transferWithAuthorization` when funded — **prohibited** (transactions).
   - *Settlement observer only*: `tools/base-watchdog` already watches
     incoming USDC to `payTo` — keep verification-only serving and treat
     watchdog alerts as the receipt that payment *actually arrived*;
     periodically reconcile against `X-PAYMENT` logs. Zero new infra.
2. **Wire check 8** (`makeRpcSettlementCheck`) and switch it to fail-closed.
3. **Persistent replay cache** (SQLite or Redis) + small idempotency window.
4. **TLS + BASE_URL** set to the public origin; add per-IP rate limiting on
   the 402 path (challenge emission is free and abuse-able).
5. **Raise the price** once there's evidence anyone wants it; 10000 atomic
   is a probe price, not a valuation.
6. Optional: list on agentic.market-style x402 directories.

## Deployment options (free-tier candidates)

The app is a plain Node HTTP server (stateless apart from the replay cache):

| Host | Free tier | Notes |
|------|-----------|-------|
| Render (Web Service) | yes (spins down when idle; cold start ~30 s+) | easiest fit; custom domains; `npm start` |
| Railway | trial credit, then ~$5/mo | best DX; not permanently free |
| Fly.io | small always-free allowance (credit-based) | needs `flyctl` + account (operator-created) |
| Cloudflare Workers / Vercel | generous | **requires porting** off `node:http` (Workers-style fetch handler); the x402 logic is portable as-is |
| Home machine + Cloudflare Tunnel | free | keeps zero-capital, but uptime = desktop uptime |

Hosting-account creation is operator-only (charter: agent may not create
accounts). Deploying anywhere is explicitly **not** done in this prototype.

## Honest demand assessment

- x402 rails are real (100M+ txs by mid-2026) but traffic skews heavily to
  agents *spending* with known brands; our own scout evidence
  (`EVIDENCE/scout-1-agent-income-mechanisms.md`) found new-provider revenue
  ≈ 0 absent distribution, and only a small fraction of x402 volume looks
  genuinely agentic.
- The *service* competes with free: anyone can call a public RPC or read
  Basescan. What a $0.01 call actually buys is **one structured, agent-native
  answer** (no RPC setup, no log decoding, one HTTP call with a receipt).
  Plausible micro-niche: agents verifying that *they themselves got paid*
  (closing the loop on x402 flows) and CI/automation payment checks.
- Expected revenue near zero until listed and noticed; marginal cost also
  ~zero. Treat as a lottery ticket + working reference implementation —
  consistent with its #4 rank in the scout's mechanism ranking, and with
  A10 (publishing MIT tooling) it doubles as portfolio evidence for Base
  Builder Grants.

## License

MIT (see LICENSE). Test keys are generated per-run throwaways and discarded;
the operation's real wallet key never touches this package (read-only RPCs only).
