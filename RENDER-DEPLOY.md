# Render deploy bundle — one command after unlock

**Status 2026-11-10:** ready. Deploy the moment a Render account exists (GitHub OAuth on render.com — same single GitHub login that unlocks CrowdCent).

## What's included

- `render.yaml` (this directory) — Blueprint: Node web service, free instance, health check `/healthz`, `NODE_ENV=production`
- Service name: `x402-base-verifier`
- Payee: `0x696344061b0f4CcFbA0b48a8390330C6b2525531` (Base), price 10000 atomic USDC = $0.01/call

## Deploy steps (agent-executed once operator completes GitHub OAuth on render.com)

1. Push this package to a new public repo `AlexLavoie42/x402-base-verifier` (sanitized like base-watchdog; publishing grant covers it).
2. In Render (browser pane, same GitHub session): New → Blueprint → select the repo → Apply. Free tier.
3. Verify `https://x402-base-verifier.onrender.com/health` → `{"ok":true}`.
4. Smoke-test the 402 challenge (`twak x402 quote` style GET → expects `accepts` with payTo our address).
5. Production hardening before listing (README §deployment): wire `makeRpcSettlementCheck` fail-closed, persistent replay cache (Render disk or KV), rate-limit the 402 path.

## Facilitator (settlement) — env-only, verified 2026-11-11

Two hosted options, both wired via `src/facilitator-select.ts`:

| Facilitator | `FACILITATOR_URL` | Auth | Chains (live `/supported`) |
|---|---|---|---|
| **PayAI** (recommended) | `https://facilitator.payai.network` | **none — no API key** | x402 v2 exact: Base `eip155:8453`, Polygon `eip155:137`, Arbitrum `eip155:42161`, BSC 56, Avalanche 43114, Solana; v1 base/polygon/arbitrum |
| Coinbase CDP | `https://api.cdp.coinbase.com/platform/v2/x402` | `CDP_API_KEY_ID` + `CDP_API_KEY` (dashboard-created) | Base/Polygon/Arbitrum/Monad/World |

PayAI was probed live without any credentials: `/supported` and `/verify` answer
without auth (`/verify` with a garbage payload returns 400 `invalid_payment_requirements`,
not 401). Setting `FACILITATOR_URL=https://facilitator.payai.network` alone — no
CDP keys — makes every payment verify AND settle on-chain into
`PAY_TO` on Base mainnet. Evidence: https://facilitator.payai.network/supported ,
directory: https://docs.x402.org/dev-tools/facilitators.md

## Then

- List on agentic.market (GitHub OAuth; free) with price $0.01/call.
- Integrate a Base Builder Code (per docs.base.org/specifications/builder-codes) so paid traffic is attributable → satisfies the $5K cohort prerequisite → apply (form: https://forms.gle/urqjBJYJjR6Vqqre6, "agents / x402 implementations" track).
- base-watchdog doubles as settlement observer (already watches USDC into payTo).
