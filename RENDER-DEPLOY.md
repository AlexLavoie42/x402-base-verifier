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

## Then

- List on agentic.market (GitHub OAuth; free) with price $0.01/call.
- Integrate a Base Builder Code (per docs.base.org/specifications/builder-codes) so paid traffic is attributable → satisfies the $5K cohort prerequisite → apply (form: https://forms.gle/urqjBJYJjR6Vqqre6, "agents / x402 implementations" track).
- base-watchdog doubles as settlement observer (already watches USDC into payTo).
