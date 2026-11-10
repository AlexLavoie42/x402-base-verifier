/**
 * Deterministic, offline Solidity pre-audit scanner (V1) — the engine behind
 * POST /scan.
 *
 * NO compiler, NO AST, NO network. The pipeline:
 *   1. normalize line endings, then strip comments and string CONTENTS while
 *      preserving every byte offset and line number (so findings point at the
 *      exact line the caller submitted);
 *   2. a light structural pass over the stripped text: function/modifier/
 *      constructor blocks (signature, visibility, modifiers, body), contract
 *      ranges + inheritance text, contract-scope state-variable names,
 *      interface-typed variable names;
 *   3. run every rule from src/rules.ts against every file (rules are
 *      line/pattern based — see the honest limitations in the report payload);
 *   4. dedupe, sort by severity, aggregate stats.
 *
 * Honest scope: this can never prove a contract safe. It distills recurring
 * bug SHAPES from real security campaigns into cheap, deterministic checks —
 * a pre-audit triage, not an audit.
 */
import { RULES } from "./rules.js";
import { SCAN_MAX_SOURCE_BYTES, SCAN_MAX_FILES } from "./config.js";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export interface Finding {
  rule: string;
  severity: Severity;
  confidence: number;
  file: string;
  line: number;
  snippet: string;
  why: string;
  fix: string;
}

export interface ScanInput {
  sources: Record<string, string>;
  solcVersion?: string;
}

export interface ScanStats {
  files: number;
  lines: number;
  rules_run: number;
  duration_ms: number;
}

export interface ScanReport {
  findings: Finding[];
  stats: ScanStats;
  disclaimer: string;
  limitations: string[];
}

/** One external-interaction site inside a function/modifier body. */
export interface CallSite {
  line: number; // 1-based
  kind: "value" | "lowlevel" | "delegatecall" | "staticcall" | "interface";
  callee: string;
  /** statement result unused (not assigned, not inside require/if/emit/return) */
  bare: boolean;
  /** assigned (e.g. destructured bool) but the flag is never checked afterwards */
  unchecked: boolean;
  args: string;
}

export interface FunctionBlock {
  kind: "function" | "constructor" | "modifier";
  name: string;
  startLine: number; // 1-based, signature line
  endLine: number; // 1-based, closing brace
  bodyStartLine: number; // 1-based, line of the opening `{`
  header: string; // signature text up to (excluding) `{`
  paramDecls: string[]; // raw parameter declaration segments
  params: string[]; // parameter names
  returns: string[]; // named return parameters (locals)
  visibility: "public" | "external" | "internal" | "private" | null;
  viewLike: boolean;
  payable: boolean;
  modifiers: string[]; // modifier invocations (onlyOwner, nonReentrant, ...)
  bodyLines: string[]; // stripped lines bodyStartLine..endLine
  bodyText: string;
  contract: ContractInfo | null;
  localNames: Set<string>; // names declared inside the block (params/returns included)
  stateWriteLines: number[]; // 1-based lines with a likely storage write
  callSites: CallSite[];
  emitted: boolean;
}

export interface ContractInfo {
  name: string;
  startLine: number; // 1-based header line
  endLine: number;
  headerText: string; // text between the contract name and `{`
  hasInitialize: boolean;
  isImplPattern: boolean; // has initialize() or inherits Initializable
  immutableDecls: { name: string; line: number }[];
  blocks: FunctionBlock[];
}

export interface FileContext {
  file: string;
  raw: string;
  rawLines: string[];
  lines: string[]; // comment/string-stripped, same line count
  text: string; // stripped, joined with \n
  blocks: FunctionBlock[];
  contracts: ContractInfo[];
  stateVars: Set<string>;
  interfaceTypedVars: Set<string>;
}

/* ------------------------------------------------------------------ */
/* Source normalization                                                */
/* ------------------------------------------------------------------ */

/**
 * Same-length copy of `raw` with line/block comments and the contents of
 * string/char literals blanked out (quotes kept), so later regex passes never
 * match commented-out code or string contents while offsets stay valid.
 */
export function stripSource(raw: string): string {
  const out: string[] = [];
  const n = raw.length;
  let state: "code" | "line" | "block" | "str" = "code";
  let quote = "";
  for (let i = 0; i < n; i++) {
    const c = raw[i]!;
    const next = i + 1 < n ? raw[i + 1]! : "";
    if (state === "code") {
      if (c === "/" && next === "/") {
        state = "line";
        out.push("  ");
        i++;
        continue;
      }
      if (c === "/" && next === "*") {
        state = "block";
        out.push("  ");
        i++;
        continue;
      }
      if (c === '"' || c === "'") {
        state = "str";
        quote = c;
        out.push(c);
        continue;
      }
      out.push(c);
      continue;
    }
    if (state === "line") {
      if (c === "\n") {
        state = "code";
        out.push("\n");
      } else out.push(" ");
      continue;
    }
    if (state === "block") {
      if (c === "*" && next === "/") {
        state = "code";
        out.push("  ");
        i++;
        continue;
      }
      out.push(c === "\n" ? "\n" : " ");
      continue;
    }
    // inside a string literal
    if (c === "\\") {
      out.push(c === undefined ? " " : "  "); // escape char + escaped char
      i++;
      continue;
    }
    if (c === quote) {
      state = "code";
      quote = "";
      out.push(c);
      continue;
    }
    out.push(c === "\n" ? "\n" : " ");
  }
  return out.join("");
}

/* ------------------------------------------------------------------ */
/* Small lexical helpers                                               */
/* ------------------------------------------------------------------ */

/**
 * Index of a real assignment `=` (also `+=`, `-=`, ...) — skips `==`, `=>`,
 * `<=`, `>=`, `!=`, and comparisons. -1 when the line assigns nothing.
 */
export function assignmentIndex(s: string): number {
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "=") continue;
    const prev = i > 0 ? s[i - 1]! : "";
    const next = i + 1 < s.length ? s[i + 1]! : "";
    if (next === "=" || next === ">") continue; // == =>
    if (prev === "=" || prev === "!" || prev === "<" || prev === ">") continue; // == <= >= !=
    return i; // plain = or augmented op=
  }
  return -1;
}

/** Sides of the first assignment on the line, LHS operator-stripped; null if none. */
export function assignmentSides(line: string): { lhs: string; rhs: string } | null {
  const eq = assignmentIndex(line);
  if (eq === -1) return null;
  const lhs = line
    .slice(0, eq)
    .replace(/[+\-*/%&|^]$/, "") // augmented assignment operator
    .trim();
  const rhs = line.slice(eq + 1).replace(/;.*$/, "").trim();
  if (!lhs) return null;
  return { lhs, rhs };
}

const RESERVED_HEADER_WORDS = new Set([
  "returns",
  "public",
  "external",
  "internal",
  "private",
  "view",
  "pure",
  "payable",
  "virtual",
  "override",
  "constant",
  "immutable",
  "memory",
  "calldata",
  "storage",
  "returns",
]);

/** View-ish interface methods we do NOT treat as state-changing interactions. */
const VIEW_METHODS = new Set([
  "balanceOf",
  "decimals",
  "symbol",
  "name",
  "totalSupply",
  "latestRoundData",
  "latestAnswer",
  "getReserves",
  "getAmountsOut",
  "getAmountsIn",
  "allowance",
  "token0",
  "token1",
  "feeTier",
  "slot0",
  "ownerOf",
  "getApproved",
]);

const INTERFACE_TYPES = new Set([
  "AggregatorV3Interface",
  "ChainlinkAggregatorV3Interface",
  "KeeperRegistryInterface",
  "IWETH9",
]);

function isInterfaceType(type: string): boolean {
  return INTERFACE_TYPES.has(type) || /^I[A-Z]/.test(type);
}

/* ------------------------------------------------------------------ */
/* Structural pass                                                     */
/* ------------------------------------------------------------------ */

const SIG_RE = /^\s*(function|constructor|modifier)\b\s*([A-Za-z_$][\w$]*)?\s*\(/;
const CONTAINER_RE = /^\s*(?:abstract\s+)?(?:contract|interface|library)\s+([A-Za-z_$][\w$]*)\s*([^{]*)\{/;
const STRUCT_ENUM_RE = /^\s*(struct|enum)\s+([A-Za-z_$][\w$]*)\s*\{/;
const STATE_VAR_RE =
  /^\s*(?:address|bool|string|bytes\d*|uint\d*|int\d*|bytes|[A-Za-z_$][\w$.]*)(?:\[[^\]]*\])*\s+(?:(?:public|private|internal|constant|immutable|override|transient)\s+)*([A-Za-z_$][\w$]*)\s*(?:;|=)/;
const MAPPING_VAR_RE = /^\s*mapping\s*\([^)]*\)\s+(?:(?:public|private|internal)\s+)*([A-Za-z_$][\w$]*)\s*(?:;|=)/;
const DECL_RE =
  /(?:^|[\s(;,])(?:uint\d*|int\d*|address(?:\s+payable)?|bool|string|bytes\d*|bytes|[A-Za-z_$][\w$.]*)(?:\[[^\]]*\])*(?:\s+(?:memory|calldata|storage|payable|indexed))?\s+([A-Za-z_$][\w$]*)\s*(?=[=;,)]|\s*=)/g;

/** Walk braces from `startLine` (0-based) until depth returns to 0. Returns 0-based end line. */
function braceWalkEnd(lines: string[], startLine: number): number {
  let depth = 0;
  let started = false;
  for (let k = startLine; k < lines.length; k++) {
    for (const ch of lines[k]!) {
      if (ch === "{") {
        depth++;
        started = true;
      } else if (ch === "}") depth--;
    }
    if (started && depth <= 0) return k;
  }
  return startLine;
}

function splitParams(s: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of s) {
    if (ch === "(" || ch === "[" || ch === "<") depth++;
    else if (ch === ")" || ch === "]" || ch === ">") depth--;
    if (ch === "," && depth === 0) {
      parts.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts.filter(Boolean);
}

function paramName(decl: string): string | null {
  const m = decl.match(/([A-Za-z_$][\w$]*)\s*$/);
  return m ? m[1]! : null;
}

/** Does this (stripped) line write to storage? Approximation, see module docs. */
function isStateWriteLine(line: string, block: FunctionBlock, ctx: FileContext): boolean {
  const t = line.trim();
  if (!t) return false;
  if (/^(require|emit|return|if|for|while|assert|unchecked)\b/.test(t)) return false;
  const knownLocal = (base: string) => block.localNames.has(base) || block.params.includes(base);

  const del = t.match(/^delete\s+([A-Za-z_$][\w$]*)/);
  if (del) {
    const base = del[1]!;
    return ctx.stateVars.has(base) && !knownLocal(base);
  }

  const push = t.match(/(?:^|[^.\w])([A-Za-z_$][\w$]*)\s*\.\s*push\s*\(/);
  if (push) {
    const base = push[1]!;
    if (knownLocal(base)) return false;
    return ctx.stateVars.has(base);
  }

  const eq = assignmentIndex(t);
  if (eq === -1) return false;
  const lhs = t
    .slice(0, eq)
    .replace(/[+\-*/%&|^]$/, "") // augmented assignment operator (`+=`, `-=`, ...)
    .trim();
  if (/\s/.test(lhs)) return false; // `uint x = ...` declaration or destructuring: not a storage write
  const base = lhs.split(/[.[]/, 1)[0] ?? "";
  if (!base || base === "message") return false;
  return ctx.stateVars.has(base) && !knownLocal(base);
}

function collectLocals(block: FunctionBlock, header: string): Set<string> {
  const names = new Set<string>([...block.params, ...block.returns]);
  const collect = (text: string) => {
    for (const m of text.matchAll(DECL_RE)) names.add(m[1]!);
  };
  collect(header);
  for (const line of block.bodyLines) collect(line);
  return names;
}

function scanCallSites(block: FunctionBlock, ctx: FileContext): CallSite[] {
  const sites: CallSite[] = [];
  block.bodyLines.forEach((line, idx) => {
    const t = line.trim();
    if (!t) return;
    const abs = block.bodyStartLine + idx;
    const hasAssign = assignmentIndex(t) !== -1;
    const wrapped = /\b(require|if|assert|emit|return|while)\s*\(/.test(t) || /\?|&&|\|\|/.test(t);
    const bare = !hasAssign && !wrapped;

    const boolDestructure = t.match(/\(\s*bool\s+([A-Za-z_$][\w$]*)\s*,/);
    const destructureUnchecked = (() => {
      if (!boolDestructure) return bare;
      const name = boolDestructure[1]!;
      const occurrences = block.bodyText.match(new RegExp(`\\b${name}\\b`, "g"))?.length ?? 0;
      return occurrences <= 1; // named once (here) but never checked
    })();

    const push = (kind: CallSite["kind"], callee: string, index: number) =>
      sites.push({ line: abs, kind, callee, bare, unchecked: destructureUnchecked, args: t.slice(index) });

    let m = t.match(/\.delegatecall\s*\(/);
    if (m) push("delegatecall", "delegatecall", m.index ?? 0);
    m = t.match(/\.staticcall\s*\(/);
    if (m) push("staticcall", "staticcall", m.index ?? 0);
    m = t.match(/\.send\s*\(/);
    if (m) push("value", "send", m.index ?? 0);
    m = t.match(/\.call\s*\{[^}]*\}/);
    if (m) {
      const valueSent = /value\s*:/.test(m[0]);
      push(valueSent ? "value" : "lowlevel", "call", m.index ?? 0);
    } else if ((m = t.match(/\.call\s*\(/))) {
      push("lowlevel", "call", m.index ?? 0);
    }
    m = t.match(/\.transferFrom\s*\(/);
    if (m) push("value", "transferFrom", m.index ?? 0);
    m = t.match(/\.transfer\s*\(/);
    if (m) push("value", "transfer", m.index ?? 0);

    // interface-typed variable calls (non-view methods not already covered above)
    for (const v of ctx.interfaceTypedVars) {
      const re = new RegExp(`\\b${v}\\s*\\.\\s*([A-Za-z_$][\\w$]*)\\s*\\(`);
      const im = t.match(re);
      if (!im) continue;
      const method = im[1]!;
      if (VIEW_METHODS.has(method)) continue;
      if (["transfer", "transferFrom", "send", "call", "delegatecall", "staticcall"].includes(method)) continue;
      if (sites.some((s) => s.line === abs && s.kind !== "interface")) continue;
      push("interface", method, im.index ?? 0);
    }
  });
  return sites;
}

export function parseFile(file: string, raw: string): FileContext {
  const normalized = raw.replace(/\r\n?/g, "\n");
  const stripped = stripSource(normalized);
  const rawLines = normalized.split("\n");
  const lines = stripped.split("\n");

  // --- contract / struct / enum ranges -------------------------------------
  const contracts: ContractInfo[] = [];
  const covered = new Set<number>(); // 0-based line indexes inside fn/struct/enum blocks
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const cm = line.match(CONTAINER_RE);
    if (cm) {
      const end = braceWalkEnd(lines, i);
      // NOTE: contract bodies are deliberately NOT "covered" — contract-scope
      // lines are exactly where state variables live; only struct/enum bodies
      // and function blocks are excluded from the state-variable pass.
      contracts.push({
        name: cm[1]!,
        startLine: i + 1,
        endLine: end + 1,
        headerText: cm[2] ?? "",
        hasInitialize: false,
        isImplPattern: /Initializable/.test(cm[2] ?? ""),
        immutableDecls: [],
        blocks: [],
      });
      i = end; // contracts cannot nest
      continue;
    }
    const sm = line.match(STRUCT_ENUM_RE);
    if (sm) {
      const end = braceWalkEnd(lines, i);
      for (let k = i; k <= end; k++) covered.add(k);
      i = end;
    }
  }

  // --- function / modifier / constructor blocks ----------------------------
  const blocks: FunctionBlock[] = [];
  let i = 0;
  while (i < lines.length) {
    const m = lines[i]!.match(SIG_RE);
    if (!m) {
      i++;
      continue;
    }
    const kind = m[1] as FunctionBlock["kind"];
    const name = m[2] ?? (kind === "constructor" ? "constructor" : "");

    // scan forward through the signature for `{` (body) or `;` (no body -> skip)
    let j = i;
    let header = "";
    let bodyStart = -1;
    let hasBody = false;
    while (j < lines.length && j <= i + 25) {
      header += (j === i ? "" : " ") + lines[j]!.trim();
      const semi = lines[j]!.indexOf(";");
      const brace = lines[j]!.indexOf("{");
      if (brace !== -1 && (semi === -1 || brace < semi)) {
        bodyStart = j;
        hasBody = true;
        break;
      }
      if (semi !== -1) break; // declaration only (interface/abstract)
      j++;
    }
    if (!hasBody || bodyStart === -1) {
      i++;
      continue;
    }
    const end = braceWalkEnd(lines, bodyStart);
    for (let k = i; k <= end; k++) covered.add(k);

    const headerToBrace = header.slice(0, header.indexOf("{") === -1 ? header.length : header.indexOf("{")).trim();
    // parameter list: from the first `(` of the signature to its match
    const open = headerToBrace.indexOf("(");
    let depth = 0;
    let close = -1;
    for (let k = open; k < headerToBrace.length; k++) {
      const ch = headerToBrace[k]!;
      if (ch === "(") depth++;
      else if (ch === ")") {
        depth--;
        if (depth === 0) {
          close = k;
          break;
        }
      }
    }
    const paramDecls = close > open ? splitParams(headerToBrace.slice(open + 1, close)) : [];
    const params = paramDecls.map((d) => paramName(d)).filter((x): x is string => x !== null);
    const after = close === -1 ? "" : headerToBrace.slice(close + 1);
    const modifiers: string[] = [];
    const vis = headerToBrace.match(/\b(public|external|internal|private)\b/);
    for (const mm of after.matchAll(/([A-Za-z_$][\w$]*)\s*(\([^()]*\))?/g)) {
      const word = mm[1]!;
      if (!RESERVED_HEADER_WORDS.has(word) && word !== vis?.[1]) modifiers.push(word);
    }
    const returns: string[] = [];
    const ret = headerToBrace.match(/returns\s*\(([^)]*)\)/);
    if (ret) {
      for (const d of splitParams(ret[1]!)) {
        const nm = paramName(d);
        if (nm) returns.push(nm);
      }
    }
    const bodyLines = lines.slice(bodyStart, end + 1);

    const block: FunctionBlock = {
      kind,
      name,
      startLine: i + 1,
      endLine: end + 1,
      bodyStartLine: bodyStart + 1,
      header: headerToBrace,
      paramDecls,
      params,
      returns,
      visibility: (vis?.[1] as FunctionBlock["visibility"]) ?? null,
      viewLike: /\b(view|pure)\b/.test(headerToBrace),
      payable: /\bpayable\b/.test(headerToBrace),
      modifiers,
      bodyLines,
      bodyText: bodyLines.join("\n"),
      contract: null,
      localNames: new Set<string>(),
      stateWriteLines: [],
      callSites: [],
      emitted: /\bemit\b/.test(bodyLines.join("\n")),
    };
    block.contract = contracts.find((c) => block.startLine >= c.startLine && block.endLine <= c.endLine) ?? null;
    if (block.contract) block.contract.blocks.push(block);
    blocks.push(block);
    i = end + 1;
  }

  // contract post-pass: initialize detection
  for (const c of contracts) {
    c.hasInitialize = c.blocks.some((b) => b.kind === "function" && /initialize/i.test(b.name));
    c.isImplPattern = c.isImplPattern || c.hasInitialize;
  }

  // --- state variables (contract scope, outside all blocks) ----------------
  const stateVars = new Set<string>();
  for (let k = 0; k < lines.length; k++) {
    if (covered.has(k)) continue;
    const line = lines[k]!;
    const vm = line.match(MAPPING_VAR_RE) ?? line.match(STATE_VAR_RE);
    if (!vm) continue;
    const name = vm[1]!;
    if (RESERVED_HEADER_WORDS.has(name)) continue;
    stateVars.add(name);
    if (/immutable/.test(line)) {
      const owner = contracts.find((c) => k + 1 >= c.startLine && k + 1 <= c.endLine);
      owner?.immutableDecls.push({ name, line: k + 1 });
    }
  }

  // --- interface-typed variables -------------------------------------------
  const interfaceTypedVars = new Set<string>();
  for (const dm of stripped.matchAll(
    /\b([A-Za-z_$][\w$]*)\s+(?:constant\s+|immutable\s+|public\s+|private\s+|internal\s+)*([A-Za-z_$][\w$]*)\b/g,
  )) {
    const type = dm[1]!;
    if (isInterfaceType(type) && !RESERVED_HEADER_WORDS.has(dm[2]!)) interfaceTypedVars.add(dm[2]!);
  }

  const ctx: FileContext = {
    file,
    raw: normalized,
    rawLines,
    lines,
    text: stripped,
    blocks,
    contracts,
    stateVars,
    interfaceTypedVars,
  };

  // --- per-block enrichment -------------------------------------------------
  for (const block of blocks) {
    block.localNames = collectLocals(block, block.header);
    block.stateWriteLines = block.bodyLines
      .map((line, idx) => (isStateWriteLine(line, block, ctx) ? block.bodyStartLine + idx : -1))
      .filter((n) => n !== -1);
    block.callSites = scanCallSites(block, ctx);
  }

  return ctx;
}

/* ------------------------------------------------------------------ */
/* Request validation (shared by tests + the route)                    */
/* ------------------------------------------------------------------ */

const SOLC_VERSION_RE = /^v?\d+\.\d+\.\d+/;

/** Returns an error string when the JSON body is not a valid scan request, else null. */
export function validateScanRequest(body: unknown): string | null {
  if (body === undefined || body === null || typeof body !== "object" || Array.isArray(body)) {
    return 'POST body must be a JSON object: { "sources": { "contracts/MyToken.sol": "pragma ..." }, "solcVersion"?: "0.8.24" }';
  }
  const obj = body as Record<string, unknown>;
  const sources = obj.sources;
  if (sources === undefined || sources === null || typeof sources !== "object" || Array.isArray(sources)) {
    return 'missing required field "sources": an object mapping file paths to Solidity source strings';
  }
  const entries = Object.entries(sources as Record<string, unknown>);
  if (entries.length === 0) return '"sources" must contain at least one file';
  if (entries.length > SCAN_MAX_FILES) return `too many files: ${entries.length} (max ${SCAN_MAX_FILES})`;
  let total = 0;
  for (const [path, src] of entries) {
    if (!path.trim()) return "source file paths must be non-empty strings";
    if (typeof src !== "string") return `source for "${path}" must be a string`;
    total += Buffer.byteLength(src, "utf8");
    if (total > SCAN_MAX_SOURCE_BYTES) {
      return `sources too large: over ${SCAN_MAX_SOURCE_BYTES} bytes total (got at least ${total} for "${path}"); split the scan`;
    }
  }
  if (obj.solcVersion !== undefined && (typeof obj.solcVersion !== "string" || !SOLC_VERSION_RE.test(obj.solcVersion))) {
    return '"solcVersion", when present, must look like a compiler version, e.g. "0.8.24"';
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Orchestration                                                       */
/* ------------------------------------------------------------------ */

export const SCAN_LIMITATIONS = [
  "No compiler or type system: findings come from deterministic line/pattern analysis over comment-stripped source; safe code can be flagged and unsafe code can be missed.",
  "Inheritance is resolved only within the submitted file set; modifiers/variables inherited from unsubmitted bases (e.g. OpenZeppelin) are inferred by name only.",
  "Storage-write detection and external-call classification are heuristics (state-variable names collected at contract scope; known call shapes); treat every finding as a lead to verify, not a verdict.",
  "Line numbers refer to the exact source text submitted (1-based, CRLF normalized).",
  "No data-flow, no symbolic execution, no exploitability proof; severity/confidence are calibrated heuristics.",
];

export const SCAN_DISCLAIMER = "automated pattern scan; not a substitute for a professional audit";

export function scanSources(input: ScanInput): ScanReport {
  const started = performance.now();
  const findings: Finding[] = [];
  const files = Object.entries(input.sources ?? {});
  const ctxs = files.map(([name, src]) => parseFile(name, src));
  // cross-file shadowing: any state variable declared anywhere in the submission
  const globalStateVars = new Set<string>(ctxs.flatMap((c) => [...c.stateVars]));

  for (const ctx of ctxs) {
    for (const rule of RULES) {
      const seen = new Set<string>();
      try {
        rule.run(ctx, globalStateVars, (hit) => {
          const line = Math.min(Math.max(1, Math.trunc(hit.line)), ctx.rawLines.length);
          const key = `${rule.id}:${line}:${hit.dedupeKey ?? ""}`;
          if (seen.has(key)) return;
          seen.add(key);
          const snippet = (ctx.rawLines[line - 1] ?? "").trim().slice(0, 200);
          findings.push({
            rule: rule.id,
            severity: hit.severity ?? rule.severity,
            confidence: hit.confidence ?? rule.confidence,
            file: ctx.file,
            line,
            snippet,
            why: hit.why ?? rule.why,
            fix: hit.fix ?? rule.fix,
          });
        });
      } catch {
        // one broken rule must never kill the scan; skip silently (rules are pure)
      }
    }
  }

  findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.rule.localeCompare(b.rule),
  );

  const lines = ctxs.reduce((sum, c) => sum + c.rawLines.length, 0);
  return {
    findings,
    stats: {
      files: ctxs.length,
      lines,
      rules_run: RULES.length,
      duration_ms: Math.max(0, Math.round(performance.now() - started)),
    },
    disclaimer: SCAN_DISCLAIMER,
    limitations: SCAN_LIMITATIONS,
  };
}
