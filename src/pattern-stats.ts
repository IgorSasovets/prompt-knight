import * as fs from "fs";
import * as path from "path";
import { Detection } from "./types";

export interface PatternStatEntry {
  matchCount: number;
  suppressedCount: number;
  lastMatchedAt?: string;
}

export type PatternStats = Record<string, PatternStatEntry>;

function statsFilePath(userConfigDir: string): string {
  return path.join(userConfigDir, "logs", "pattern-stats.json");
}

function readStats(filePath: string): PatternStats {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return parsed as PatternStats;
    }
    return {};
  } catch {
    return {};
  }
}

function writeStats(filePath: string, stats: PatternStats): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(filePath), 0o700);
  fs.writeFileSync(filePath, JSON.stringify(stats, null, 2), { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

/**
 * Persists per-pattern match/suppression counts across hook invocations (REQ-SI-05),
 * keyed by `Detection.patternId` — uniform across all four detection sources (tier1's
 * category, a custom pattern id, `gitleaks:<RuleID>`, `tier2:<category>`).
 *
 * Each hook invocation is a fresh process, so this does a read-merge-write against a
 * small JSON file; under concurrent invocations this accepts last-write-wins rather
 * than file locking — an acceptable tradeoff for a local, single-user, low-concurrency
 * tool. Never throws: a failure here must never affect enforcement, so it's caught and
 * returned as an optional warning instead.
 */
export function recordPatternActivity(
  matched: Detection[],
  suppressed: Detection[],
  userConfigDir: string
): { warning?: string } {
  if (matched.length === 0 && suppressed.length === 0) return {};

  const filePath = statsFilePath(userConfigDir);
  try {
    const stats = readStats(filePath);
    const now = new Date().toISOString();

    for (const d of matched) {
      const entry = stats[d.patternId] ?? { matchCount: 0, suppressedCount: 0 };
      entry.matchCount += 1;
      entry.lastMatchedAt = now;
      stats[d.patternId] = entry;
    }
    for (const d of suppressed) {
      const entry = stats[d.patternId] ?? { matchCount: 0, suppressedCount: 0 };
      entry.suppressedCount += 1;
      stats[d.patternId] = entry;
    }

    writeStats(filePath, stats);
    return {};
  } catch (err) {
    return { warning: `PromptKnight: failed to update pattern-stats.json: ${(err as Error).message}` };
  }
}
