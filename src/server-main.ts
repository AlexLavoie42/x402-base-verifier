/**
 * Runnable entry: `npm start` (tsx). Local prototype — do NOT deploy as-is.
 * Env: PORT, BASE_URL, RPC_URLS, PRICE_ATOMIC, SCAN_PRICE_ATOMIC, PAY_TO,
 * FACILITATOR_URL, CDP_API_KEY_ID, CDP_API_KEY (see src/config.ts and
 * .env.example).
 *
 * Facilitator wiring (src/facilitator-select.ts, the middleware's standard
 * verification path):
 *   - FACILITATOR_URL set: HTTPFacilitatorClient against that facilitator —
 *     it verifies AND settles on-chain, so the rail can earn. With
 *     CDP_API_KEY_ID + CDP_API_KEY set (Coinbase CDP facilitator:
 *     https://api.cdp.coinbase.com/platform/v2/x402) every call carries a
 *     freshly minted EdDSA bearer JWT. Going live is PURELY these env vars
 *     plus one deploy — no code change.
 *   - default (unset): in-process verify-only facilitator — full EIP-3009
 *     verification plus a read-only on-chain authorizationState check over
 *     the public RPC fallback list. Nothing is ever signed, sent, or settled
 *     on-chain by this process (receive-only operation), and a startup
 *     WARNING says so: settlement disabled, the rail cannot earn.
 */
import { loadConfig, USDC } from "./config.js";
import { makeRpcClients } from "./verdict.js";
import { makeRpcSettlementCheck } from "./settlement.js";
import { selectFacilitator } from "./facilitator-select.js";
import { createApp } from "./server.js";

const cfg = loadConfig();
const { facilitator, hosted, warning } = selectFacilitator(cfg, {
  settlementCheck: makeRpcSettlementCheck(cfg.rpcUrls, USDC),
});

const app = createApp({
  config: cfg,
  clients: makeRpcClients(cfg.rpcUrls),
  facilitator,
  log: (m) => console.log(new Date().toISOString(), m),
});

app.listen(cfg.port, () => {
  console.log(`x402-endpoint v2 (Base payment verification) listening on http://localhost:${cfg.port}`);
  console.log(`  price       : ${cfg.priceAtomic} atomic USDC per /verify call`);
  console.log(`  scan price  : ${cfg.scanPriceAtomic} atomic USDC per POST /scan call (Solidity pre-audit)`);
  console.log(`  payTo       : ${cfg.payTo}`);
  console.log(
    hosted
      ? `  facilitator : ${cfg.facilitatorUrl} (HTTP${cfg.facilitatorApiKey !== null ? ", CDP bearer JWT auth" : ""})`
      : "  facilitator : in-process verify-only (EIP-3009 + read-only authorizationState; nothing settled on-chain)",
  );
  console.log(`  rpcs        : ${cfg.rpcUrls.join(", ")}`);
  if (warning !== null) console.warn(warning);
  console.log(`Try: curl "http://localhost:${cfg.port}/verify?tx=0x<hash>&to=0x<addr>&min=0.01" -i  # -> 402 + PAYMENT-REQUIRED header`);
});
