#!/usr/bin/env node
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as readline from "readline";
import { loadConfig, resolveSandboxedPath } from "./config-loader";
import { checkRedosSafety } from "./redos-check";
import { CandidateSuggestion, FeedbackRecord, normalizeShape, suggestPatterns } from "./pattern-suggester";
import { PatternDefinition } from "./types";

export function readFeedbackRecords(feedbackLogPath: string): FeedbackRecord[] {
  if (!fs.existsSync(feedbackLogPath)) return [];
  const raw = fs.readFileSync(feedbackLogPath, "utf8");
  const records: FeedbackRecord[] = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (
        typeof parsed.category === "string" &&
        typeof parsed.evidencePreview === "string" &&
        typeof parsed.confidence === "number"
      ) {
        records.push(parsed as FeedbackRecord);
      }
    } catch {
      // skip a malformed line rather than fail the whole read
    }
  }
  return records;
}

/** Rewrites feedback.jsonl, dropping only records whose signature was just approved —
 * their evidence has graduated into a real pattern, so shorter retention is the more
 * secure choice. Skipped suggestions' records are left untouched. */
export function purgeFeedbackRecords(feedbackLogPath: string, signaturesToPurge: ReadonlySet<string>): void {
  if (signaturesToPurge.size === 0 || !fs.existsSync(feedbackLogPath)) return;
  const raw = fs.readFileSync(feedbackLogPath, "utf8");
  const kept = raw.split("\n").filter((line) => {
    if (!line.trim()) return false;
    try {
      const parsed = JSON.parse(line);
      const signature = `${parsed.category}::${normalizeShape(parsed.evidencePreview ?? "")}`;
      return !signaturesToPurge.has(signature);
    } catch {
      return false;
    }
  });
  fs.writeFileSync(feedbackLogPath, kept.length > 0 ? `${kept.join("\n")}\n` : "", { mode: 0o600 });
}

export function readApprovedSignatures(statePath: string): Set<string> {
  try {
    const raw = fs.readFileSync(statePath, "utf8");
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed.approvedSignatures)) return new Set(parsed.approvedSignatures);
  } catch {
    // no state file yet, or it's malformed — start fresh rather than fail the CLI
  }
  return new Set();
}

export function writeApprovedSignatures(statePath: string, signatures: ReadonlySet<string>): void {
  fs.mkdirSync(path.dirname(statePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(statePath, JSON.stringify({ approvedSignatures: [...signatures] }, null, 2), { mode: 0o600 });
}

export interface AppendResult {
  ok: boolean;
  reason?: string;
}

/**
 * Validates (compile + ReDoS-safety check, REQ-SI-04) and appends an approved pattern
 * to the custom pattern file. `customPatternsPath` must already be the sandboxed,
 * resolved path (the caller resolves it via `resolveSandboxedPath`, the same helper
 * `tier1-engine.ts`'s loader uses) — this function only does validation + the file
 * read/write.
 */
export function appendCustomPattern(customPatternsPath: string, pattern: PatternDefinition): AppendResult {
  const check = checkRedosSafety(pattern.regex, pattern.flags ?? "");
  if (!check.safe) return { ok: false, reason: check.reason };
  try {
    new RegExp(pattern.regex, pattern.flags ?? "");
  } catch (err) {
    return { ok: false, reason: `pattern does not compile: ${(err as Error).message}` };
  }

  let existing: PatternDefinition[] = [];
  try {
    if (fs.existsSync(customPatternsPath)) {
      const parsed = JSON.parse(fs.readFileSync(customPatternsPath, "utf8"));
      if (Array.isArray(parsed)) existing = parsed;
    }
  } catch {
    existing = [];
  }

  existing.push(pattern);
  fs.writeFileSync(customPatternsPath, JSON.stringify(existing, null, 2));
  return { ok: true };
}

function formatSuggestion(s: CandidateSuggestion): string {
  const example = s.examples[0] ?? "";
  return `${s.category} (${s.hitCount} hits)   ${s.regex}\n    e.g. "${example}"`;
}

async function runInteractiveReview(): Promise<void> {
  const homedir = os.homedir();
  const pluginRoot = path.resolve(__dirname, "..", "..");
  const projectRoot = process.cwd();
  const { config, userConfigDir } = loadConfig(pluginRoot, projectRoot, homedir);

  const logDir = path.join(userConfigDir, "logs");
  const feedbackLogPath = path.join(logDir, "feedback.jsonl");
  const statePath = path.join(logDir, "pattern-suggestions-state.json");

  const records = readFeedbackRecords(feedbackLogPath);
  const approvedSignatures = readApprovedSignatures(statePath);
  const suggestions = suggestPatterns(records, {
    minHits: config.feedback.minHitsForSuggestion,
    approvedSignatures,
  });

  if (suggestions.length === 0) {
    console.log("No new pattern suggestions.");
    return;
  }

  const sandboxErrors: string[] = [];
  const customPatternsPath = resolveSandboxedPath(
    config.tier1.customPatternsFile,
    pluginRoot,
    [pluginRoot, userConfigDir, projectRoot],
    "tier1.customPatternsFile",
    sandboxErrors
  );
  if (!customPatternsPath) {
    console.error(`Cannot write approved patterns: ${sandboxErrors.join(" ")}`);
    return;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q: string): Promise<string> => new Promise((resolve) => rl.question(q, resolve));

  console.log(`Found ${suggestions.length} new pattern suggestion(s):`);
  const purgedSignatures = new Set<string>();
  let approvedCount = 0;
  let skippedCount = 0;

  for (const suggestion of suggestions) {
    let current = suggestion;
    let decided = false;
    while (!decided) {
      console.log(`\n${formatSuggestion(current)}`);
      const answer = (await ask("[a]pprove [s]kip [e]dit > ")).trim().toLowerCase();

      if (answer === "a") {
        const result = appendCustomPattern(customPatternsPath, {
          id: current.id,
          category: current.category,
          regex: current.regex,
        });
        if (result.ok) {
          approvedSignatures.add(current.shapeSignature);
          purgedSignatures.add(current.shapeSignature);
          approvedCount += 1;
          console.log(`Approved "${current.id}".`);
        } else {
          console.log(`Could not approve: ${result.reason}`);
        }
        decided = true;
      } else if (answer === "s") {
        skippedCount += 1;
        decided = true;
      } else if (answer === "e") {
        const newRegex = (await ask("New regex> ")).trim();
        const check = checkRedosSafety(newRegex);
        if (!check.safe) {
          console.log(`Rejected: ${check.reason}`);
          continue;
        }
        current = { ...current, regex: newRegex };
      } else {
        console.log('Please answer "a", "s", or "e".');
      }
    }
  }

  rl.close();
  writeApprovedSignatures(statePath, approvedSignatures);
  purgeFeedbackRecords(feedbackLogPath, purgedSignatures);
  console.log(`\nApproved ${approvedCount}, skipped ${skippedCount}.`);
}

if (require.main === module) {
  void runInteractiveReview();
}
