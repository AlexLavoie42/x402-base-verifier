/**
 * Read-only maintenance script: confirms the EIP-712 domain of native USDC on
 * Base that the payment verifier relies on, by comparing the contract's live
 * DOMAIN_SEPARATOR() against locally computed candidates. Also probes that
 * authorizationState(address, bytes32) (EIP-3009) is callable.
 *
 * Makes only read-only RPC calls (eth_call). Safe under the operation's
 * no-transactions charter.
 *
 * Run: npm run domain-check
 */
import { createPublicClient, http, keccak256, toHex, encodeAbiParameters } from "viem";

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;
const RPC_URLS = ["https://base.drpc.org", "https://mainnet.base.org"];

const erc3009Abi = [
  { name: "DOMAIN_SEPARATOR", type: "function", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { name: "version", type: "function", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  {
    name: "authorizationState",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "authorizer", type: "address" },
      { name: "nonce", type: "bytes32" },
    ],
    outputs: [{ type: "bool" }],
  },
] as const;

function domainSeparator(name: string, version: string, chainId: bigint, verifyingContract: string): `0x${string}` {
  // struct EIP712Domain { string name; string version; uint256 chainId; address verifyingContract; }
  const typeHash = keccak256(
    toHex("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
  );
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "address" },
      ],
      [typeHash, keccak256(toHex(name)), keccak256(toHex(version)), chainId, verifyingContract as `0x${string}`]
    )
  );
}

async function main() {
  let lastError: unknown = null;
  for (const url of RPC_URLS) {
    try {
      const client = createPublicClient({ transport: http(url) });
      const onChain = (await client.readContract({
        address: USDC,
        abi: erc3009Abi,
        functionName: "DOMAIN_SEPARATOR",
      })) as `0x${string}`;
      const version = (await client.readContract({
        address: USDC,
        abi: erc3009Abi,
        functionName: "version",
      })) as string;
      for (const [name, ver] of [["USD Coin", "2"], ["USDC", "2"], ["USD Coin", "1"]] as const) {
        const local = domainSeparator(name, ver, 8453n, USDC);
        console.log(`rpc=${url} name="${name}" version="${ver}" -> ${local === onChain ? "MATCH" : "no match"}`);
      }
      console.log("on-chain DOMAIN_SEPARATOR:", onChain);
      console.log("contract version():", version);
      const authState = await client.readContract({
        address: USDC,
        abi: erc3009Abi,
        functionName: "authorizationState",
        args: ["0x0000000000000000000000000000000000000001", keccak256(toHex("x402-probe"))],
      });
      console.log("authorizationState(dummy) =", authState);
      return;
    } catch (e) {
      lastError = e;
      console.error(`rpc ${url} failed: ${(e as Error).message.slice(0, 120)}`);
    }
  }
  throw lastError ?? new Error("no RPCs configured");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
