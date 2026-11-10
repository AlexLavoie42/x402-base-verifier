/**
 * Runnable entry: `npm start` (tsx). Local prototype — do NOT deploy as-is.
 * Env: PORT, BASE_URL, RPC_URLS, PRICE_ATOMIC, PAY_TO (see src/config.ts).
 */
import { loadConfig } from "./config.js";
import { makeRpcClients } from "./verdict.js";
import { createApp } from "./server.js";

const cfg = loadConfig();
const server = createApp({
  config: cfg,
  clients: makeRpcClients(cfg.rpcUrls),
  log: (m) => console.log(new Date().toISOString(), m),
});

server.listen(cfg.port, () => {
  console.log(`x402-endpoint (Base payment verification) listening on http://localhost:${cfg.port}`);
  console.log(`  price : ${cfg.priceAtomic} atomic USDC per /verify call`);
  console.log(`  payTo : ${cfg.payTo}`);
  console.log(`  rpcs  : ${cfg.rpcUrls.join(", ")}`);
  console.log(`Try: curl "http://localhost:${cfg.port}/verify?tx=0x<hash>&to=0x<addr>&min=0.01" -i  # -> 402 challenge`);
});
