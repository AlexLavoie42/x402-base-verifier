/**
 * The V1 rule library for the Solidity pre-audit scanner — 28 deterministic
 * pattern rules distilled from recurring findings of real security campaigns
 * (CTF/audit patterns: reentrancy shapes, ERC4626 share inflation, proxy
 * initialization pitfalls, oracle staleness, weak randomness, ...).
 *
 * HOW TO READ A RULE: every rule is a pure function over one parsed file
 * (FileContext from src/scanner.ts) that reports line-anchored hits. There is
 * no data-flow, no type checker, no inheritance graph beyond the submitted
 * files — each rule therefore carries a `confidence` (0-1) and the report
 * ships with honest limitations. Rules are meant to produce verifiable LEADS
 * ("this line looks like X, here is why and the usual fix"), never verdicts.
 *
 * Rule lanes (kept disjoint so one line is not double-reported):
 *   value lane      .transfer( .transferFrom( .send( .call{value:...}
 *                   -> reentrancy-state-after-external-call (when unguarded)
 *   non-value lane  plain .call( .staticcall( interface calls (non-view)
 *                   -> cei-ordering
 *   delegatecall    -> delegatecall-dynamic-target (its own rule)
 */
import type { CallSite, ContractInfo, FileContext, Finding, FunctionBlock, Severity } from "./scanner.js";
import { assignmentSides } from "./scanner.js";

export interface RuleHit {
  line: number; // 1-based
  severity?: Severity;
  confidence?: number;
  why?: string;
  fix?: string;
  dedupeKey?: string;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  confidence: number;
  why: string;
  fix: string;
  run: (ctx: FileContext, globalStateVars: Set<string>, report: (hit: RuleHit) => void) => void;
}

/* ------------------------------------------------------------------ */
/* shared helpers                                                      */
/* ------------------------------------------------------------------ */

const PRIVILEGED_FN_RE =
  /^(mint|burn|withdraw|withdrawAll|sweep|rescue|harvest|liquidate|upgrade|pause|unpause|blacklist|setFee\w*|setTreasury|setOwner|setOperator|setStrategy|setParams|claimFees|drain|recover)\b/;

const RANDOM_CONTEXT_RE = /random|seed|entropy|lottery|raffle|winner|dice|shuffle|jackpot|pick/i;

const ACCESS_CONTROL_HINT_RE = /msg\.sender\s*==|onlyOwner|onlyRole|hasRole|onlyAdmin|onlyOperator|onlyGovernance|onlyGuardian|onlyMinter|onlyPauser|\bauth\b|onlyAuthorized/;

function hasGuard(block: FunctionBlock): boolean {
  return block.modifiers.some((m) => /nonReentrant|noReentrant|locked|whenNotPaused.*[Rr]eentr/i.test(m)) ||
    /\bnonReentrant\b/.test(block.header);
}

function valueSites(block: FunctionBlock): CallSite[] {
  return block.callSites.filter((s) => s.kind === "value");
}

function nonValueSites(block: FunctionBlock): CallSite[] {
  return block.callSites.filter((s) => s.kind === "lowlevel" || s.kind === "staticcall" || s.kind === "interface");
}

/** Address-typed parameter names of a block (from the raw parameter declarations). */
function addressParams(block: FunctionBlock): string[] {
  return block.paramDecls.filter((d) => /\baddress\b/.test(d)).map((d) => d.match(/([A-Za-z_$][\w$]*)\s*$/)?.[1] ?? "").filter(Boolean);
}

function reportAt(report: (hit: RuleHit) => void, block: FunctionBlock): void {
  report({ line: block.startLine });
}

/* ------------------------------------------------------------------ */
/* rules                                                               */
/* ------------------------------------------------------------------ */

const floatingPragma: Rule = {
  id: "floating-pragma",
  title: "Floating pragma (^ / open >=)",
  severity: "low",
  confidence: 0.9,
  why: "A caret or open >= pragma compiles against any future patch release; deployed verification and audits are pinned to exact versions.",
  fix: 'Pin the pragma to the tested version, e.g. `pragma solidity 0.8.24;` (a range like >=0.8.24 <0.9.0 is acceptable if deliberate).',
  run: (ctx, _g, report) => {
    ctx.lines.forEach((line, idx) => {
      const m = line.match(/^\s*pragma\s+solidity\s+([^;]+);/);
      if (!m) return;
      const spec = m[1]!.trim();
      if (/[\^]/.test(spec) || (/>=/.test(spec) && !/</.test(spec))) report({ line: idx + 1 });
    });
  },
};

const missingSpdx: Rule = {
  id: "missing-spdx",
  title: "No SPDX license identifier",
  severity: "info",
  confidence: 0.95,
  why: "Without an SPDX-License-Identifier the file has no machine-readable license and solc emits a warning; it also signals unreviewed/generated code.",
  fix: 'Add a license comment on line 1, e.g. `// SPDX-License-Identifier: MIT`.',
  run: (ctx, _g, report) => {
    if (!/SPDX-License-Identifier/.test(ctx.raw)) report({ line: 1 });
  },
};

const txOriginAuth: Rule = {
  id: "tx-origin-auth",
  title: "tx.origin used (likely for authentication)",
  severity: "high",
  confidence: 0.9,
  why: "tx.origin is the transaction sender, not the immediate caller: phishing/forwarder tricks make victims execute authenticated actions, and tx.origin breaks under smart-contract wallets.",
  fix: "Authenticate with msg.sender (or role checks); keep tx.origin out of authorization logic entirely.",
  run: (ctx, _g, report) => {
    ctx.lines.forEach((line, idx) => {
      if (/tx\s*\.\s*origin/.test(line)) report({ line: idx + 1 });
    });
  },
};

const selfdestructRemnant: Rule = {
  id: "selfdestruct-remnant",
  title: "selfdestruct/suicide remnant",
  severity: "critical",
  confidence: 0.95,
  why: "selfdestruct (ex-suicide) lets a privileged or compromised caller delete the contract code and force-send its balance; classic leftover from tutorials that becomes a kill-switch vulnerability.",
  fix: "Remove the selfdestruct/suicide path; if lifecycle control is truly required, gate it behind timelocked governance and document it.",
  run: (ctx, _g, report) => {
    ctx.lines.forEach((line, idx) => {
      if (/\b(selfdestruct|suicide)\s*\(/.test(line)) report({ line: idx + 1 });
    });
  },
};

const delegatecallDynamicTarget: Rule = {
  id: "delegatecall-dynamic-target",
  title: "delegatecall with a dynamic target",
  severity: "high",
  confidence: 0.7,
  why: "delegatecall executes attacker-supplied (or user-influenced) code in this contract's storage context — a single bad target is full storage takeover.",
  fix: "Restrict delegatecall to hardcoded/immutable implementation addresses set at deploy time; never derive the target from calldata, memory or user state.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      for (const site of block.callSites.filter((s) => s.kind === "delegatecall")) {
        const args = site.args;
        const firstArg = (args.slice(args.indexOf("(") + 1).split(/[),]/)[0] ?? "").trim();
        const dynamic =
          /msg\.sender/.test(firstArg) ||
          block.params.includes(firstArg) ||
          block.localNames.has(firstArg);
        if (dynamic) {
          report({
            line: site.line,
            severity: "critical",
            confidence: 0.75,
            why: `The delegatecall target on this line ("${firstArg.slice(0, 40) || "see line"}") traces back to a parameter or local — attacker-controlled code runs in this contract's storage context.`,
            fix: "Pin the implementation address (immutable/constant set at construction) and only pass DATA dynamically, never the target.",
          });
        } else {
          report({
            line: site.line,
            severity: "info",
            confidence: 0.5,
            why: "delegatecall with a fixed target — verify the target can never be overwritten (no setter, not storage-derived).",
            fix: "Confirm the target is immutable and that no initializer/admin path can change it.",
          });
        }
      }
    }
  },
};

const weakRandomness: Rule = {
  id: "weak-randomness",
  title: "Block-derived randomness",
  severity: "high",
  confidence: 0.75,
  why: "block.timestamp / blockhash / prevrandao are observable and influenceable by validators and MEV bots; using them for winners or secrets is exploitable.",
  fix: "Use an external randomness source with commit-reveal (e.g. Chainlink VRF) or a provably-fair beacon; never seed security decisions from block properties.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      const context = RANDOM_CONTEXT_RE.test(block.name + " " + block.bodyText);
      for (let idx = 0; idx < block.bodyLines.length; idx++) {
        const line = block.bodyLines[idx]!;
        const abs = block.bodyStartLine + idx;
        if (/blockhash\s*\(/.test(line)) {
          report({ line: abs, severity: "high", confidence: 0.75, why: "blockhash() is a known block property miners/validators choose; it is not a source of unpredictability.", fix: "Replace with commit-reveal or a VRF." });
        } else if (/block\s*\.\s*(timestamp|number|difficulty|prevrandao)/.test(line) && context && !block.viewLike) {
          report({ line: abs });
        }
      }
    }
  },
};

const uncheckedLowLevelCall: Rule = {
  id: "unchecked-low-level-call",
  title: "Low-level call result ignored",
  severity: "medium",
  confidence: 0.75,
  why: "`.call`/`.send` return a bool instead of reverting; ignoring it (bare statement, or a destructured flag never tested) silently swallows failures.",
  fix: "Check the returned flag: `require(ok, \"...\")` — or use `.transfer`/SafeERC20 helpers that revert on failure.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      for (const site of block.callSites) {
        if (!["lowlevel", "staticcall", "value"].includes(site.kind)) continue;
        if (site.callee === "transfer" || site.callee === "transferFrom") continue; // separate rule
        if (site.bare) {
          report({ line: site.line, why: "The call is a bare statement — its success bool is discarded, so a failing call looks successful.", fix: "Capture the result and require it, e.g. `(bool ok, ) = to.call{...}(\"\"); require(ok);`." });
        } else if (site.unchecked) {
          report({ line: site.line, why: "The returned bool is destructured but never checked afterwards — the failure path is dead code.", fix: "Add `require(<flag>, \"call failed\")` right after the call." });
        }
      }
    }
  },
};

const unhandledTransferReturn: Rule = {
  id: "unhandled-transfer-return",
  title: "ERC20 transfer return value ignored",
  severity: "medium",
  confidence: 0.65,
  why: "Non-standard tokens (USDT et al.) return false instead of reverting; a bare `token.transfer(...)` statement hides failed transfers. (Rule is name-based: an ETH `.transfer` on the same line would be a false positive — it reverts on failure.)",
  fix: "Wrap in require(...), use SafeERC20 (safeTransfer/safeTransferFrom), or OZ's forceApprove-era helpers.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      for (const site of block.callSites.filter((s) => s.callee === "transfer" || s.callee === "transferFrom")) {
        if (site.bare) report({ line: site.line });
      }
    }
  },
};

const reentrancyStateAfterCall: Rule = {
  id: "reentrancy-state-after-external-call",
  title: "State written after an external call (reentrancy shape)",
  severity: "high",
  confidence: 0.6,
  why: "A value-carrying external call (transfer/call{value:}/send) happens BEFORE storage is updated: the callee can re-enter and replay the not-yet-updated state (checks-effects-interactions violation).",
  fix: "Reorder to checks -> effects -> interactions (write state first, transfer last) and/or apply a nonReentrant guard.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      if (block.kind !== "function" || hasGuard(block)) continue;
      for (const site of valueSites(block)) {
        if (block.stateWriteLines.some((w) => w > site.line)) {
          report({
            line: site.line,
            confidence: site.callee === "call" ? 0.65 : 0.6,
          });
        }
      }
    }
  },
};

const ceiOrdering: Rule = {
  id: "cei-ordering",
  title: "Effects after external interactions (CEI ordering)",
  severity: "medium",
  confidence: 0.5,
  why: "Storage is written after a non-value external call (plain call/staticcall/interface call). Even without value transfer, a malicious callee can re-enter via callbacks/view surprises and observe half-updated state.",
  fix: "Move all state changes before any external interaction (checks-effects-interactions).",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      if (block.kind !== "function") continue;
      for (const site of nonValueSites(block)) {
        if (block.stateWriteLines.some((w) => w > site.line)) report({ line: site.line });
      }
    }
  },
};

const erc20ApproveRace: Rule = {
  id: "erc20-approve-race",
  title: "ERC20 approve() race pattern",
  severity: "medium",
  confidence: 0.6,
  why: "approve() overwrites the whole allowance and is front-runnable: a spender can front-run a lowering approval and spend both old and new amounts.",
  fix: "Use SafeERC20 forceApprove (OZ v5), or the decrease/increase-allowance pattern; for tokens that must be approve(0)-reset first, do it atomically.",
  run: (ctx, _g, report) => {
    const mitigated = /forceApprove|safeApprove|safeIncreaseAllowance|safeDecreaseAllowance/.test(ctx.text) || /\.approve\s*\([^)]*,\s*0\s*\)/.test(ctx.text);
    if (mitigated) return;
    ctx.lines.forEach((line, idx) => {
      if (/\.approve\s*\(/.test(line)) report({ line: idx + 1 });
    });
  },
};

const missingZeroAddressCheck: Rule = {
  id: "missing-zero-address-check",
  title: "Setter/initializer missing zero-address check",
  severity: "medium",
  confidence: 0.55,
  why: "An address parameter is written straight into storage without `!= address(0)` — fat-fingered or griefed zero addresses brick admin/fee/receiver slots that often have no reset path.",
  fix: 'Add `require(param != address(0), "zero address")` before the first storage write involving the parameter.',
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      if (block.kind !== "function") continue;
      if (/address\(0\)/.test(block.bodyText)) continue;
      const candidates = addressParams(block);
      if (!candidates.length) continue;
      let hit = false;
      for (const w of block.stateWriteLines) {
        const sides = assignmentSides(ctx.lines[w - 1] ?? "");
        if (!sides) continue;
        if (candidates.some((p) => new RegExp(`\\b${p}\\b`).test(sides.rhs))) hit = true;
      }
      if (hit) reportAt(report, block);
    }
  },
};

const erc4626FirstDepositorInflation: Rule = {
  id: "erc4626-first-depositor-inflation",
  title: "ERC4626-style vault without virtual shares (first-depositor inflation)",
  severity: "medium",
  confidence: 0.5,
  why: "Share math proportional to totalShares/totalAssets from a zero baseline is vulnerable to the donation/first-depositor attack: donate assets before the first (or round-number) deposit to mint 0 shares or steal later depositors' value.",
  fix: "Hold virtual shares/assets (OpenZeppelin's _decimalsOffset / initial shares minted to address(0)), or round the first mint up and donations down.",
  run: (ctx, _g, report) => {
    const vaultish = /ERC4626/.test(ctx.text) || (/\btotalShares\b/.test(ctx.text) && /\btotalAssets\b/.test(ctx.text));
    if (!vaultish) return;
    const mitigated = /offset|INITIAL_SHARES|MINIMUM_SHARES|_FIRST|dead|DEAD/i.test(ctx.text);
    if (mitigated) return;
    for (const block of ctx.blocks) {
      if (block.kind !== "function" || !/^(deposit|mint)$/.test(block.name)) continue;
      if (/(\w+)\s*=\s*\w+\s*\*\s*\w+\s*\/\s*\w+/.test(block.bodyText) || /mulDiv\s*\(/.test(block.bodyText)) {
        reportAt(report, block);
      }
    }
  },
};

const unboundedUserArrayLoop: Rule = {
  id: "unbounded-user-array-loop",
  title: "Unbounded loop over a user-supplied array",
  severity: "medium",
  confidence: 0.7,
  why: "The loop bound is a calldata array length chosen by the caller — unbounded iteration gives block-gas-limit griefing (and outright DoS of batch endpoints).",
  fix: "Cap iterations (`require(users.length <= MAX_BATCH)`), or process in bounded chunks / pull-based pattern.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      if (block.kind !== "function") continue;
      const arrayParams = block.paramDecls.filter((d) => /\[\]/.test(d)).map((d) => d.match(/([A-Za-z_$][\w$]*)\s*$/)?.[1] ?? "").filter(Boolean);
      if (!arrayParams.length) continue;
      for (let idx = 0; idx < block.bodyLines.length; idx++) {
        const line = block.bodyLines[idx]!;
        const m = line.match(/for\s*\([^;]*;\s*[A-Za-z_$][\w$]*\s*<\s*([A-Za-z_$][\w$]*)\s*\.\s*length/);
        if (m && arrayParams.includes(m[1]!)) report({ line: block.bodyStartLine + idx });
      }
    }
  },
};

const stateVariableShadowing: Rule = {
  id: "state-variable-shadowing",
  title: "Parameter/local shadows a state variable",
  severity: "medium",
  confidence: 0.5,
  why: "A parameter or local shares its name with a state variable (possibly inherited from a submitted file): readers (and auditors) easily mistake which one a line touches — a recurring source of real bugs.",
  fix: "Rename to the trailing-underscore convention (`owner_`) or a distinct name so no scope silently shadows storage.",
  run: (ctx, globalStateVars, report) => {
    for (const block of ctx.blocks) {
      const paramClashes = block.params.filter((p) => globalStateVars.has(p) && !p.endsWith("_"));
      const localClashes = [...block.localNames].filter(
        (n) => globalStateVars.has(n) && !block.params.includes(n) && !n.endsWith("_") && !block.returns.includes(n),
      );
      const all = [...new Set([...paramClashes, ...localClashes])];
      if (all.length) {
        report({ line: block.startLine, why: `Name(s) ${all.join(", ")} shadow state variable(s) declared elsewhere in the submitted sources.`, dedupeKey: all.join(",") });
      }
    }
  },
};

const memoryArrayPush: Rule = {
  id: "memory-array-push",
  title: "push() on a memory array",
  severity: "low",
  confidence: 0.6,
  why: "Dynamic push on memory arrays is only valid for narrow solc cases (empty `new T[](0)` arrays since 0.8.x); it usually means a storage/memory mix-up and older compilers reject it outright.",
  fix: "If storage growth was intended, drop `memory`; if a fixed scratch buffer was intended, size it (`new uint256[](n)`) and index into it.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      const memoryArrays = new Set<string>();
      for (const m of block.bodyText.matchAll(/([A-Za-z_$][\w$]*)\[\]\s+memory\s+([A-Za-z_$][\w$]*)/g)) memoryArrays.add(m[2]!);
      for (const m of block.bodyText.matchAll(/([A-Za-z_$][\w$]*)\s*=\s*new\s+[A-Za-z_$][\w$.]*\[\]\(/g)) memoryArrays.add(m[1]!);
      if (!memoryArrays.size) continue;
      for (let idx = 0; idx < block.bodyLines.length; idx++) {
        const line = block.bodyLines[idx]!;
        const m = line.match(/([A-Za-z_$][\w$]*)\s*\.\s*push\s*\(/);
        if (m && memoryArrays.has(m[1]!)) report({ line: block.bodyStartLine + idx });
      }
    }
  },
};

const unsafeUintDowncast: Rule = {
  id: "unsafe-uint-downcast",
  title: "Unchecked uint/int downcast",
  severity: "medium",
  confidence: 0.5,
  why: "Casting to a narrower integer silently truncates high bits (uint256 -> uint128 etc.); in share/amount math this is a classic precision/overflow bug.",
  fix: "Use SafeCast (`SafeCast.toUint128(x)`) or an explicit range require before the cast.",
  run: (ctx, _g, report) => {
    const SAFECAST_RE = /\b(?:uint|int)(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248)\s*\(/;
    ctx.lines.forEach((line, idx) => {
      if (!SAFECAST_RE.test(line)) return;
      if (/toUint\d+\(|toInt\d+\(/.test(line)) return; // safe-cast already used on this line
      report({ line: idx + 1 });
    });
  },
};

const divisionBeforeMultiplication: Rule = {
  id: "division-before-multiplication",
  title: "Division before multiplication (precision loss)",
  severity: "medium",
  confidence: 0.5,
  why: "Solidity integer division truncates: `x / d * n` loses the remainder BEFORE scaling, systematically under-crediting users (rounding-leak exploits feed on exactly this).",
  fix: "Reorder to multiply first (`x * n / d`) or use mulDiv (FullMath) when products can overflow.",
  run: (ctx, _g, report) => {
    const RE = /[\w)\]]\s*\/\s*[\w(][\w.)\[\]]*\s*\*\s*[\w(]/;
    ctx.lines.forEach((line, idx) => {
      if (RE.test(line)) report({ line: idx + 1 });
    });
  },
};

const feeOnTransferAssumption: Rule = {
  id: "fee-on-transfer-assumption",
  title: "Fee-on-transfer token assumed to deliver full amount",
  severity: "medium",
  confidence: 0.5,
  why: "The transfer is accounted with the NOMINAL amount while fee-on-transfer tokens deliver less; the shortfall is silently socialized or bricks accounting.",
  fix: "Measure delivered amounts: balanceOf(this) before/after diff (or skim the delta) and credit that, not the parameter.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      const transfers = block.callSites.filter((s) => s.callee === "transfer" || s.callee === "transferFrom");
      if (!transfers.length) continue;
      const balanceChecks = (block.bodyText.match(/balanceOf\s*\(/g) ?? []).length;
      if (balanceChecks >= 2) continue; // before/after diff present
      const augCredit = /\+=|=\s*\w+\s*\+/.test(block.bodyText);
      if (augCredit) {
        const t = transfers[0]!;
        report({ line: t.line, why: "Token transfer credited with a nominal amount and no before/after balanceOf measurement — fee-on-transfer and deflationary tokens will desync accounting.", fix: "Use balanceOf deltas around the transfer and credit the received amount." });
      }
    }
  },
};

const swapMissingDeadline: Rule = {
  id: "swap-missing-deadline",
  title: "Swap with type(uint256).max deadline",
  severity: "medium",
  confidence: 0.75,
  why: "Passing type(uint256).max as the swap deadline disables the timeliness check: a sandwiched/backlogged mempool lets the trade execute at arbitrary future prices.",
  fix: "Pass a real deadline (`block.timestamp + SLIPPAGE_WINDOW`) and a sane amountOutMin.",
  run: (ctx, _g, report) => {
    const SWAP_RE = /swap(?:Exact\w+For\w+|\w+ForExact\w+)|exactInput(?:Single)?|exactOutput(?:Single)?/;
    ctx.lines.forEach((line, idx) => {
      if (!SWAP_RE.test(line)) return;
      const stmt = [line, ctx.lines[idx + 1] ?? "", ctx.lines[idx + 2] ?? ""].join(" ");
      if (/type\s*\(\s*uint256\s*\)\s*\.\s*max/.test(stmt)) report({ line: idx + 1 });
    });
  },
};

const oracleNoStalenessCheck: Rule = {
  id: "oracle-no-staleness-check",
  title: "Oracle read without staleness check",
  severity: "medium",
  confidence: 0.6,
  why: "Single-source Chainlink-style reads that ignore updatedAt (or use deprecated latestAnswer) accept prices from dead/LRO-down feeds — the root of the largest oracle exploits.",
  fix: "Unpack latestRoundData's updatedAt and require freshness (`updatedAt + HEARTBEAT >= block.timestamp`); reject non-positive answers; never use latestAnswer.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      for (let idx = 0; idx < block.bodyLines.length; idx++) {
        const line = block.bodyLines[idx]!;
        const abs = block.bodyStartLine + idx;
        if (/\.latestAnswer\s*\(/.test(line)) {
          report({ line: abs, confidence: 0.7, why: "latestAnswer is the deprecated single-value API with no round info — no staleness validation is even possible.", fix: "Switch to latestRoundData() and check answer > 0 and updatedAt freshness." });
        } else if (/\.latestRoundData\s*\(/.test(line) && !/updatedAt/.test(block.bodyText)) {
          report({ line: abs });
        }
      }
    }
  },
};

const immutableInProxyImpl: Rule = {
  id: "immutable-in-proxy-impl",
  title: "Immutable in a proxy implementation",
  severity: "low",
  confidence: 0.45,
  why: "In an upgradeable implementation, immutables are frozen into the implementation's runtime code at ITS deployment: every proxy shares the same value and initialize() can never change it per-proxy.",
  fix: "If the value must be per-proxy, move it to initialized storage; keep it immutable only if deliberately implementation-global.",
  run: (ctx, _g, report) => {
    for (const c of ctx.contracts) {
      if (!c.isImplPattern) continue;
      for (const decl of c.immutableDecls) {
        report({ line: decl.line, why: `Immutable "${decl.name}" in implementation "${c.name}" is baked into the impl deployment — every proxy using this impl shares one value.`, dedupeKey: decl.name });
      }
    }
  },
};

const implConstructorStateWrite: Rule = {
  id: "impl-constructor-state-write",
  title: "Constructor writes storage in a proxy implementation",
  severity: "medium",
  confidence: 0.55,
  why: "The implementation's constructor never runs for proxies: these storage writes only exist on the standalone impl deployment, so proxied instances start with uninitialized slots.",
  fix: "Move initialization into initialize() guarded by the initializer modifier; keep only _disableInitializers() in the constructor.",
  run: (ctx, _g, report) => {
    for (const c of ctx.contracts) {
      if (!c.isImplPattern) continue;
      const ctor = c.blocks.find((b) => b.kind === "constructor");
      if (!ctor || /_disableInitializers/.test(ctor.bodyText)) continue;
      for (const w of ctor.stateWriteLines) {
        const sides = assignmentSides(ctx.lines[w - 1] ?? "");
        const base = sides?.lhs.split(/[.[]/, 1)[0] ?? "";
        if (base && c.immutableDecls.some((d) => d.name === base)) continue; // immutable assignment is the one legal constructor job
        report({ line: w });
      }
    }
  },
};

const missingInitializerGuard: Rule = {
  id: "missing-initializer-guard",
  title: "initialize() without initializer guard",
  severity: "high",
  confidence: 0.7,
  why: "An initialize() without the initializer/onlyInitializing modifier (or an explicit initialized flag) can be called by anyone — attacker initializes the proxy first and owns every privileged slot.",
  fix: "Mark it `initializer` (OZ Initializable) or `reinitializer(n)` for upgrades, and set owner inside it.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      if (block.kind !== "function" || !/^initialize/i.test(block.name)) continue;
      if (block.modifiers.some((m) => /initializer|onlyInitializing|reinitializer/i.test(m))) continue;
      if (/require\s*\(\s*!\s*\w*[Ii]nitiali/.test(block.bodyText)) continue;
      reportAt(report, block);
    }
  },
};

const missingDisableInitializers: Rule = {
  id: "missing-disable-initializers",
  title: "Implementation constructor missing _disableInitializers()",
  severity: "medium",
  confidence: 0.65,
  why: "Without _disableInitializers() in the implementation constructor, anyone can initialize the raw implementation contract itself and e.g. become its owner (a known class of high findings).",
  fix: "Add `constructor() { _disableInitializers(); }` to every implementation contract.",
  run: (ctx, _g, report) => {
    for (const c of ctx.contracts) {
      if (!c.hasInitialize) continue;
      const ctor = c.blocks.find((b) => b.kind === "constructor");
      if (!ctor) continue;
      if (!/_disableInitializers/.test(ctor.bodyText)) {
        report({ line: ctor.startLine, why: `Constructor of "${c.name}" (which has initialize()) does not call _disableInitializers() — the implementation itself stays initializable.`, dedupeKey: c.name });
      }
    }
  },
};

const adminFnMissingEvent: Rule = {
  id: "admin-fn-missing-event",
  title: "Admin/state-changing function emits no event",
  severity: "low",
  confidence: 0.5,
  why: "Privileged state changes without events are unauditable off-chain: indexers and monitoring cannot see who changed what, which slows incident response and hides misuse.",
  fix: "Emit a dedicated event for each admin change (old + new value) before/after the write.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      if (block.kind !== "function" || block.viewLike) continue;
      const privileged = block.modifiers.some((m) => /^only|^auth|^governed/.test(m)) || /^set[A-Z]/.test(block.name);
      if (!privileged) continue;
      if (block.stateWriteLines.length > 0 && !block.emitted) reportAt(report, block);
    }
  },
};

const privilegedFnUnprotected: Rule = {
  id: "privileged-fn-unprotected",
  title: "Privileged-looking function without access control",
  severity: "high",
  confidence: 0.55,
  why: "The name/shape says admin (mint/burn/sweep/setFee/...), it is external, writes storage or moves value — yet no onlyOwner/onlyRole guard and no msg.sender check protects it.",
  fix: "Add the appropriate access control (onlyOwner/onlyRole/AccessManager) or, for self-custody functions, an explicit check on the affected account.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      if (block.kind !== "function" || !block.name || !PRIVILEGED_FN_RE.test(block.name)) continue;
      if (block.visibility !== "public" && block.visibility !== "external") continue;
      if (block.viewLike) continue;
      if (block.modifiers.some((m) => /^only|^auth|^governed/.test(m))) continue;
      if (ACCESS_CONTROL_HINT_RE.test(block.bodyText)) continue;
      const movesValue = block.callSites.some((s) => s.kind === "value");
      if (!block.stateWriteLines.length && !movesValue) continue;
      // self-custody heuristic: writes keyed by msg.sender, or value paid to
      // msg.sender, are (usually) user-owned flows, not admin surface
      const writes = block.stateWriteLines.map((w) => ctx.lines[w - 1] ?? "");
      const valueLines = block.callSites.filter((s) => s.kind === "value").map((s) => ctx.lines[s.line - 1] ?? "");
      const selfWrites = writes.length > 0 && writes.every((l) => /msg\.sender/.test(l));
      const selfPays = valueLines.length > 0 && valueLines.every((l) => /msg\.sender/.test(l));
      if (selfWrites || selfPays) continue;
      reportAt(report, block);
    }
  },
};

const modifierSideEffects: Rule = {
  id: "modifier-side-effects",
  title: "Modifier with side effects",
  severity: "medium",
  confidence: 0.6,
  why: "A modifier performs external calls or storage writes: modifiers run on EVERY use, hide effects from reviewers scanning function bodies, and external calls inside them are prime reentrancy surface. (Guard-style writes to lock/status flags are exempt.)",
  fix: "Keep modifiers to cheap invariant checks; move external calls and business-state writes into the function body.",
  run: (ctx, _g, report) => {
    for (const block of ctx.blocks) {
      if (block.kind !== "modifier") continue;
      const badWrites = block.stateWriteLines.filter((w) => {
        const sides = assignmentSides(ctx.lines[w - 1] ?? "");
        const base = sides?.lhs.split(/[.[]/, 1)[0] ?? "";
        return !/lock|status|guard|mutex|enter|initiali|pause/i.test(base);
      });
      const external = block.callSites.filter(
        (s) => s.kind === "value" || s.kind === "lowlevel" || s.kind === "interface" || s.kind === "delegatecall",
      );
      if (external.length || badWrites.length) {
        report({ line: block.startLine, why: external.length ? `Modifier "${block.name}" performs external call(s) (e.g. ${external[0]!.callee}) outside the function body's review surface.` : `Modifier "${block.name}" writes business state directly.`, fix: "Move side effects into the guarded function; keep the modifier a pure precondition." });
      }
    }
  },
};

export const RULES: Rule[] = [
  floatingPragma,
  missingSpdx,
  txOriginAuth,
  selfdestructRemnant,
  delegatecallDynamicTarget,
  weakRandomness,
  uncheckedLowLevelCall,
  unhandledTransferReturn,
  reentrancyStateAfterCall,
  ceiOrdering,
  erc20ApproveRace,
  missingZeroAddressCheck,
  erc4626FirstDepositorInflation,
  unboundedUserArrayLoop,
  stateVariableShadowing,
  memoryArrayPush,
  unsafeUintDowncast,
  divisionBeforeMultiplication,
  feeOnTransferAssumption,
  swapMissingDeadline,
  oracleNoStalenessCheck,
  immutableInProxyImpl,
  implConstructorStateWrite,
  missingInitializerGuard,
  missingDisableInitializers,
  adminFnMissingEvent,
  privilegedFnUnprotected,
  modifierSideEffects,
];
