/**
 * Runnable entry: `npm start` (tsx). Local prototype — do NOT deploy as-is.
 * Env: PORT, BASE_URL, RPC_URLS, PRICE_ATOMIC, PAY_TO, FACILITATOR_URL
 * (see src/config.ts).
 *
 * Facilitator wiring (the middleware's standard verification path):
 *   - default: in-process verify-only facilitator — full EIP-3009 verification
 *     plus a read-only on-chain authorizationState check over the public RPC
 *     fallback list. Nothing is ever signed, sent, or settled on-chain by this
 *     process (receive-only operation).
 *   - FACILITATOR_URL set: HTTPFacilitatorClient against that facilitator.
 *     It must support x402 v2 "exact" on eip155:8453 or the middleware will
 *     reject every request (Coinbase's hosted x402.org facilitator does NOT
 *     cover Base mainnet as of 2026-11).
 */
import { HTTPFacilitatorClient } from "@x402/core/server";
import { loadConfig, USDC } from "./config.js";
import { makeRpcClients } from "./verdict.js";
import { makeRpcSettlementCheck } from "./settlement.js";
import { createLocalFacilitator } from "./local-facilitator.js";
import { createApp } from "./server.js";

const cfg = loadConfig();
const facilitator =
  cfg.facilitatorUrl !== null
    ? new HTTPFacilitatorClient({ url: cfg.facilitatorUrl })
    : createLocalFacilitator({ settlementCheck: makeRpcSettlementCheck(cfg.rpcUrls, USDC) });

const app = createApp({
  config: cfg,
  clients: makeRpcClients(cfg.rpcUrls),
  facilitator,
  log: (m) => console.log(new Date().toISOString(), m),
});

app.listen(cfg.port, () => {
  console.log(`x402-endpoint v2 (Base payment verification) listening on http://localhost:${cfg.port}`);
  console.log(`  price       : ${cfg.priceAtomic} atomic USDC per /verify call`);
  console.log(`  payTo       : ${cfg.payTo}`);
  console.log(
    cfg.facilitatorUrl !== null
      ? `  facilitator : ${cfg.facilitatorUrl} (HTTP)`
      : "  facilitator : in-process verify-only (EIP-3009 + read-only authorizationState; nothing settled on-chain)",
  );
  console.log(`  rpcs        : ${cfg.rpcUrls.join(", ")}`);
  console.log(`Try: curl "http://localhost:${cfg.port}/verify?tx=0x<hash>&to=0x<addr>&min=0.01" -i  # -> 402 + PAYMENT-REQUIRED header`);
});
