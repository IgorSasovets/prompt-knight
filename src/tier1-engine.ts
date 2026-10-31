import * as fs from "fs";
import * as path from "path";
import { Worker } from "worker_threads";
import { Detection, PatternDefinition, Tier1Config } from "./types";
import { checkRedosSafety } from "./redos-check";
import { resolveSandboxedPath } from "./config-loader";
import { WorkerRequest, WorkerResponse } from "./pattern-worker";

export interface CompiledPattern {
  id: string;
  category: string;
  regex: RegExp;
  source: string;
  flags: string;
  trusted: boolean; // built-in (shipped, reviewed) vs custom (user-supplied, untrusted)
}

export interface LoadPatternsResult {
  patterns: CompiledPattern[];
  loadErrors: string[];
}

function readPatternDefinitions(filePath: string): { definitions: PatternDefinition[]; error?: string } {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return { definitions: [], error: `${filePath} must contain a JSON array of pattern definitions` };
    }
    return { definitions: parsed as PatternDefinition[] };
  } catch (err) {
    return { definitions: [], error: `Failed to read/parse ${filePath}: ${(err as Error).message}` };
  }
}

function compileOne(def: PatternDefinition, trusted: boolean, loadErrors: string[]): CompiledPattern | null {
  const flags = def.flags ?? "";
  const check = checkRedosSafety(def.regex, flags);
  if (!check.safe) {
    loadErrors.push(`Skipping pattern "${def.id}": ${check.reason}`);
    return null;
  }
  try {
    const regex = new RegExp(def.regex, flags.includes("g") ? flags : `${flags}g`);
    return { id: def.id, category: def.category, regex, source: def.regex, flags, trusted };
  } catch (err) {
    loadErrors.push(`Skipping pattern "${def.id}": failed to compile: ${(err as Error).message}`);
    return null;
  }
}

/**
 * Loads the built-in pattern library plus, where configured and sandbox-safe, the
 * custom pattern file (REQ-T1-01/03, T1.4/T1.9). Built-ins are only filtered by the
 * per-category toggles in `tier1.patterns`; everything goes through the ReDoS check.
 */
export function loadPatterns(
  pluginRoot: string,
  tier1Config: Tier1Config,
  allowedRoots: string[]
): LoadPatternsResult {
  const loadErrors: string[] = [];
  const patterns: CompiledPattern[] = [];

  const builtinPath = path.join(pluginRoot, "patterns", "builtin.json");
  const builtin = readPatternDefinitions(builtinPath);
  if (builtin.error) loadErrors.push(builtin.error);
  for (const def of builtin.definitions) {
    const toggleKey = def.category as keyof Tier1Config["patterns"];
    if (tier1Config.patterns[toggleKey] === false) continue;
    const compiled = compileOne(def, true, loadErrors);
    if (compiled) patterns.push(compiled);
  }

  const resolvedCustomPath = resolveSandboxedPath(
    tier1Config.customPatternsFile,
    pluginRoot,
    allowedRoots,
    "tier1.customPatternsFile",
    loadErrors
  );
  if (resolvedCustomPath && fs.existsSync(resolvedCustomPath)) {
    const custom = readPatternDefinitions(resolvedCustomPath);
    if (custom.error) loadErrors.push(custom.error);
    for (const def of custom.definitions) {
      const compiled = compileOne(def, false, loadErrors);
      if (compiled) patterns.push(compiled);
    }
  }

  return { patterns, loadErrors };
}

export function isAllowlisted(matchedText: string, allowlist: string[]): boolean {
  return allowlist.some((entry) => matchedText.includes(entry));
}

/**
 * Collapses detections that report the identical matched secret value, regardless of
 * which detector found it (REQ-GL-05). Earlier entries win, so callers that want
 * tier1's more specific category name to take priority over gitleaks' should
 * concatenate tier1 detections first.
 */
export function dedupeDetections(detections: Detection[]): Detection[] {
  const seenByValue = new Set<string>();
  const seenByLocation = new Set<string>();
  return detections.filter((d) => {
    if (seenByValue.has(d.matchedText)) return false;
    const locationKey = `${d.category}:${d.index}:${d.length}`;
    if (seenByLocation.has(locationKey)) return false;
    seenByValue.add(d.matchedText);
    seenByLocation.add(locationKey);
    return true;
  });
}

function runTrusted(pattern: CompiledPattern, text: string): Detection[] {
  const detections: Detection[] = [];
  const regex = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    detections.push({
      category: pattern.category,
      source: "tier1",
      patternId: pattern.id,
      index: match.index,
      length: match[0].length,
      matchedText: match[0],
    });
    if (match[0].length === 0) regex.lastIndex += 1;
  }
  return detections;
}

let workerHandle: Worker | null = null;
let nextRequestId = 1;

function getWorker(workerScriptPath: string): Worker {
  if (!workerHandle) {
    workerHandle = new Worker(workerScriptPath);
  }
  return workerHandle;
}

function respawnWorker(workerScriptPath: string): Worker {
  if (workerHandle) {
    void workerHandle.terminate();
  }
  workerHandle = new Worker(workerScriptPath);
  return workerHandle;
}

/**
 * Runs a single untrusted (custom) pattern against `text` in a worker thread, bounded
 * by `timeoutMs`. On timeout the worker is terminated — a real guarantee, not a best
 * effort — and the pattern is treated as non-matching (REQ-T1-05).
 */
async function runUntrusted(
  pattern: CompiledPattern,
  text: string,
  timeoutMs: number,
  workerScriptPath: string,
  timeouts: string[]
): Promise<Detection[]> {
  const worker = getWorker(workerScriptPath);
  const id = nextRequestId++;
  const request: WorkerRequest = { id, source: pattern.source, flags: pattern.flags, text };

  return new Promise<Detection[]>((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      timeouts.push(`Pattern "${pattern.id}" exceeded ${timeoutMs}ms and was aborted`);
      respawnWorker(workerScriptPath);
      resolve([]);
    }, timeoutMs);

    const onMessage = (response: WorkerResponse) => {
      if (response.id !== id || settled) return;
      settled = true;
      clearTimeout(timer);
      worker.off("message", onMessage);
      if (response.error || !response.matches) {
        resolve([]);
        return;
      }
      resolve(
        response.matches.map((m) => ({
          category: pattern.category,
          source: "custom" as const,
          patternId: pattern.id,
          index: m.index,
          length: m.length,
          matchedText: m.matchedText,
        }))
      );
    };

    worker.on("message", onMessage);
    worker.postMessage(request);
  });
}

export function shutdownPatternWorker(): void {
  if (workerHandle) {
    void workerHandle.terminate();
    workerHandle = null;
  }
}

export interface ScanOptions {
  maxPromptBytes: number;
  patternTimeoutMs: number;
  allowlist: string[];
  workerScriptPath: string;
}

export interface ScanResult {
  detections: Detection[];
  suppressed: Detection[];
  timeouts: string[];
}

export function truncateToByteLimit(text: string, maxBytes: number): string {
  if (Buffer.byteLength(text, "utf8") <= maxBytes) return text;
  // Binary-search the largest prefix (in UTF-16 code units) whose UTF-8 byte length
  // stays within the bound, avoiding a split multi-byte character at the boundary.
  let low = 0;
  let high = text.length;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (Buffer.byteLength(text.slice(0, mid), "utf8") <= maxBytes) {
      low = mid;
    } else {
      high = mid - 1;
    }
  }
  return text.slice(0, low);
}

export async function scan(text: string, patterns: CompiledPattern[], options: ScanOptions): Promise<ScanResult> {
  const bounded = truncateToByteLimit(text, options.maxPromptBytes);
  const timeouts: string[] = [];
  let detections: Detection[] = [];

  for (const pattern of patterns) {
    if (pattern.trusted) {
      const start = Date.now();
      const found = runTrusted(pattern, bounded);
      if (Date.now() - start > options.patternTimeoutMs) {
        timeouts.push(`Pattern "${pattern.id}" exceeded ${options.patternTimeoutMs}ms (built-in, measured post-hoc)`);
      }
      detections = detections.concat(found);
    } else {
      const found = await runUntrusted(pattern, bounded, options.patternTimeoutMs, options.workerScriptPath, timeouts);
      detections = detections.concat(found);
    }
  }

  const filtered = detections.filter((d) => !isAllowlisted(d.matchedText, options.allowlist));
  const suppressed = detections.filter((d) => isAllowlisted(d.matchedText, options.allowlist));
  const deduped = dedupeDetections(filtered);

  return { detections: deduped, suppressed, timeouts };
}
