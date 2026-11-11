# x402-base-verifier — two x402 v2 pay-per-call API endpoints on Base

Live at **https://x402-verifier.onrender.com** — machine-payable via the
[x402 v2](https://x402.org) protocol (402 challenge → EIP-3009 signature →
result). No API keys, no accounts: an x402-capable client pays per call and
gets a structured JSON answer.

| Endpoint | Method | Price | What you get |
|---|---|---|---|
| `/verify` | GET / POST | **$0.01** (10000 atomic USDC, Base) | Did transaction `0x…` transfer ≥ X USDC (or ETH) to address `0x…`? Structured verdict over public Base RPCs. |
| `/scan` | POST | **$1.00** (100000 atomic USDC, Base) | Solidity pre-audit scan: 28 deterministic exploit-pattern rules over up to ~200 KB of source, each finding with severity / confidence / line / why / fix. |
| `/` and `/health` | GET | free | Service descriptor / liveness. |

## Try it right now (see the 402 challenge, free)

```bash
curl -si "https://x402-verifier.onrender.com/verify"
```

```text
HTTP/1.1 402 Payment Required
payment-required: eyJ4NDAyVmVyc2lvbiI6MiwiZXJyb3IiOiJQYXltZW50IHJlcXVpcmVkIiwicmVzb3VyY2UiOnsidXJsIjoiaHR0cHM6Ly94NDAyLXZlcmlmaWVyLm9ucmVuZGVyLmNvbS92ZXJpZnkiLCJkZXNjcmlwdGlvbiI6IkJhc2UgcGF5bWVudCB2ZXJpZmljYXRpb246IC4uLiIsInNlcnZpY2VOYW1lIjoiYmFzZS1wYXltZW50LXZlcmlmaWNhdGlvbiIsInRhZ3MiOlsiYmFzZSIsInVzZGMiLCJwYXltZW50cyIsInZlcmlmaWNhdGlvbiIsIng0MDIiXX0sImFjY2VwdHMiOlt7InNjaGVtZSI6ImV4YWN0IiwibmV0d29yayI6ImVpcDE1NTo4NDUzIiwiYW1vdW50IjoiMTAwMDAiLCJhc3NldCI6IjB4ODMzNTg5ZkNENmVEYjZFMDhmNGM3QzMyRDRmNzFiNTRiZEEwMjkxMyIsInBheVRvIjoiMHg2OTYzNDQwNjFiMGY0Q2NGYkEwYjQ4YTgzOTAzMzBDNmIyNTI1NTMxIiwibWF4VGltZW91dFNlY29uZHMiOjMwLCJleHRyYSI6eyJuYW1lIjoiVVNEIENvaW4iLCJ2ZXJzaW9uIjoiMiJ9fV0sImV4dGVuc2lvbnMiOnsiYmF6YWFyIjp7Li4ufX19
{"error":"Payment required"}
```

The base64 `PAYMENT-REQUIRED` header decodes to the x402 v2 challenge:
`x402Version: 2`, the resource description, and one `accepts` entry —
`scheme "exact"`, network `eip155:8453` (Base mainnet), `amount 10000`
atomic USDC ($0.01), asset `0x8335…2913` (native USDC on Base), `payTo`,
and a `maxTimeoutSeconds: 30` validity window. The `extensions.bazaar`
block carries input schema + output example so x402 discovery indexers
([agentic.market](https://agentic.market)) can catalog the route.

## How an x402-capable client pays

The three-step loop (exactly what any x402 client library automates —
e.g. the official `x402-fetch` wrapper, or CDP's x402 clients):

1. **Call unpaid → receive the 402.** Decode the `PAYMENT-REQUIRED` header.
2. **Sign an EIP-3009 `transferWithAuthorization`** over the USDC-on-Base
   EIP-712 domain (`{ name: "USD Coin", version: "2", chainId: 8453,
   verifyingContract: 0x8335…2913 }`) with `to = payTo` and
   `value ≥ 10000`, then build the payment header: base64 of
   `{ x402Version: 2, scheme: "exact", payload: { signature, authorization } }`.
3. **Retry with `PAYMENT-SIGNATURE: <that base64>` → 200 + result**
   (and a `PAYMENT-RESPONSE` receipt header).

A complete working client for this exact loop lives in
[`scripts/smoke.ts`](scripts/smoke.ts) (throwaway key, read-only RPCs):

```ts
// sketch of smoke.ts — full runnable version in the repo
const unpaid = await fetch(`${base}/verify?tx=0x…&to=0x…&min=0.01&token=usdc`);   // 402
const challenge = JSON.parse(Buffer.from(
  unpaid.headers.get("payment-required")!, "base64").toString());
const authorization = buildEip3009Authorization(challenge);        // payTo, amount, 30s window
const signature = await payer.signTypedData(usdcOnBaseDomain, TRANSFER_WITH_AUTHORIZATION_TYPES, authorization);
const paymentHeader = Buffer.from(JSON.stringify(
  { x402Version: 2, scheme: "exact", payload: { signature, authorization } })).toString("base64");
const paid = await fetch(`${base}/verify?tx=0x…`, { headers: { "PAYMENT-SIGNATURE": paymentHeader } }); // 200
```

Or with the generic x402 fetch wrapper (no manual signing):

```ts
import { wrapper } from "x402-fetch";
const res = await wrapper(fetch)(
  "https://x402-verifier.onrender.com/verify?tx=0x<hash>&to=0x<addr>&min=0.01&token=usdc",
  { payer: privateKeyToAccount("0x…") }, // wallet holding USDC on Base
);
const verdict = await res.json();
```

### /verify — arguments

`tx` (required, 0x… 32-byte Base tx hash), `to` (optional recipient
filter), `min` (optional decimal minimum, default 0), `token`
(`usdc|eth`, default usdc) — as query params (GET) or a JSON body (POST).
Invalid arguments are rejected with a free 400 **before** payment is
demanded; you never pay for an unanswerable request. Real verdict shape:

```json
{
  "paid": true, "amount": "11.81", "block": 55749678,
  "txHash": "0x7153acfd79cd3c7119f096807be6307ba9ef9fab72d505cfa9437806dcd973c9",
  "from": "0xff9592258b601e0592570295894ba19b505c0257",
  "token": "usdc", "verifiedAt": "2026-11-10T19:51:55.295Z", "chain": "base",
  "found": true, "matched": 1, "minRequested": "0.01",
  "to": "0x870435Ee7bD072bCeD4Ef74b405D7C8a436ea973"
}
```

Plausible buyers: agents verifying that *they themselves got paid* on Base
(closing the loop on x402 flows), CI/automation payment checks — one
structured HTTP call instead of RPC setup + log decoding.

### POST /scan — Solidity pre-audit scanner ($1.00)

```bash
curl -X POST https://x402-verifier.onrender.com/scan \
  -H "content-type: application/json" \
  -d '{"sources":{"contracts/Vault.sol":"// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\ncontract Vault { mapping(address=>uint256) public balances; function withdraw(uint256 a) external { require(balances[msg.sender]>=a); (bool s,)=msg.sender.call{value:a}(\"\"); balances[msg.sender]-=a; } }"},"solcVersion":"0.8.24"}'
# → 402 + PAYMENT-REQUIRED; retry with PAYMENT-SIGNATURE to get the report:
```

```json
{
  "findings": [
    {
      "rule": "reentrancy-state-after-external-call",
      "severity": "high",
      "confidence": 0.6,
      "file": "contracts/Vault.sol",
      "line": 1,
      "snippet": "(bool s,)=msg.sender.call{value:a}(\"\"); balances[msg.sender]-=a;",
      "why": "A value-carrying external call happens BEFORE storage is updated …",
      "fix": "Reorder to checks → effects → interactions … and/or nonReentrant guard."
    }
  ],
  "stats": { "files": 1, "lines": 1, "rules_run": 28, "duration_ms": 2 },
  "disclaimer": "automated pattern scan; not a substitute for a professional audit"
}
```

**Rule families (28 rules)**: reentrancy shapes & CEI ordering, unchecked
call/transfer results, ERC4626 first-depositor inflation, zero-address
checks, unbounded user-array loops, block.timestamp/blockhash randomness,
tx.origin auth, state-variable shadowing, ERC20 approve race, missing admin
events, delegatecall to dynamic targets, selfdestruct remnants,
proxy-init pitfalls, uint downcasts, division-before-multiplication,
fee-on-transfer assumptions, swap deadlines, oracle staleness
(latestRoundData/latestAnswer), memory-array push, modifier side effects,
unprotected privileged functions, floating pragmas, missing SPDX.

**Honest limitations** (shipped in every response): no compiler/AST/type
system — line/pattern analysis over comment-stripped source; false
positives and misses both possible; inheritance resolved only within
submitted files. A triage tool producing verifiable leads, never a proof
of safety. Zero findings ≠ audited. Buyers who want real depth should
still hire an auditor — this finds the cheap kills first.

## Honest status box (updated 2026-11-10)

- **Earnings to date: $0.00.** No paid call has happened yet.
- **Bazaar indexing**: the route passes Coinbase's official x402 validator
  (all preflight checks green, simulation `accepted`) and carries full
  `extensions.bazaar` metadata, but [agentic.market](https://agentic.market)
  indexing is gated on a first **settled** payment through the CDP
  facilitator. No submission API or PR process exists — listing is purely
  automatic ([docs](https://docs.cdp.coinbase.com/x402/seller/get-discovered)).
- **Settlement posture**: this deploy runs an in-process verify-only
  facilitator (Coinbase's hosted facilitator does not cover Base mainnet
  as of 2026-11). Payments are fully validated off-chain — EIP-712
  signature recovery against the USDC-on-Base domain, payTo/amount/window
  checks, nonce replay guard, read-only on-chain `authorizationState` —
  but nothing is ever signed or broadcast by this server. `payTo`
  receives nothing until a Base-mainnet facilitator is wired
  (`FACILITATOR_URL`, one env var, no code change).
- **/scan validation gap**: the validator probes GET by default and
  `/scan` is POST-only (a bodyless POST is correctly 400'd for free
  before payment), so `/scan` does not currently pass the standalone
  validator even though its bazaar metadata is declared. `/verify` does.

## Repo layout / run / test

```
src/config.ts     constants + env (per-route prices, payTo, RPC fallback list)
src/server.ts     express wiring: /verify + /scan behind official @x402/express v2 middleware
src/local-facilitator.ts   in-process verify-only FacilitatorClient (default deploy)
src/scanner.ts    /scan engine: normalization + structural pass + report
src/rules.ts      the 28 pattern rules (severity/confidence/why/fix)
src/verdict.ts    the paid product: receipt/tx → verdict (USDC logs or ETH value)
test/fixtures/    Solidity snippets: one per rule family + 2 clean false-positive controls
scripts/smoke.ts  live end-to-end 402 → sign → 200 demo (throwaway key, read-only RPCs)
```

```bash
npm install
npm test            # offline test suite
npm run typecheck
npm start           # http://localhost:3000
npx tsx scripts/smoke.ts   # live loop against real Base data
```

Env: `PORT`, `BASE_URL`, `RPC_URLS`, `PRICE_ATOMIC` (default 10000 =
$0.01), `SCAN_PRICE_ATOMIC` (default 100000 = $1.00), `PAY_TO`
(`0x696344061b0f4CcFbA0b48a8390330C6b2525531` — the operation's
receive-only wallet), `FACILITATOR_URL` (unset = in-process facilitator).

## Links

- Live service: https://x402-verifier.onrender.com (`GET /` = machine-readable descriptor)
- x402 protocol: https://x402.org — spec, client libraries, facilitator docs
- Get discovered (Bazaar): https://docs.cdp.coinbase.com/x402/seller/get-discovered
- agentic.market: https://agentic.market — Coinbase's public x402 service directory
- Deployment: Render (`render.yaml`); migration notes in [MIGRATION.md](MIGRATION.md)

## License

MIT (see LICENSE). Test keys are generated per-run throwaways and
discarded; the operation's real wallet key never touches this package
(read-only RPCs only).
