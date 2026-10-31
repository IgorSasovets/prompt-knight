import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { recordPatternActivity } from "../src/pattern-stats";
import { Detection } from "../src/types";

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function detection(patternId: string, category = patternId): Detection {
  return { category, source: "tier1", patternId, index: 0, length: 5, matchedText: "xxxxx" };
}

test("records match and suppressed counts for new patterns", () => {
  const userConfigDir = mkTmp("promptknight-stats-");
  recordPatternActivity([detection("aws_keys")], [detection("private_ips")], userConfigDir);

  const statsPath = path.join(userConfigDir, "logs", "pattern-stats.json");
  const stats = JSON.parse(fs.readFileSync(statsPath, "utf8"));
  assert.equal(stats.aws_keys.matchCount, 1);
  assert.equal(stats.aws_keys.suppressedCount, 0);
  assert.equal(stats.private_ips.matchCount, 0);
  assert.equal(stats.private_ips.suppressedCount, 1);
  assert.ok(typeof stats.aws_keys.lastMatchedAt === "string");
});

test("accumulates counts across repeated calls (read-merge-write)", () => {
  const userConfigDir = mkTmp("promptknight-stats-");
  recordPatternActivity([detection("aws_keys")], [], userConfigDir);
  recordPatternActivity([detection("aws_keys"), detection("aws_keys")], [], userConfigDir);

  const statsPath = path.join(userConfigDir, "logs", "pattern-stats.json");
  const stats = JSON.parse(fs.readFileSync(statsPath, "utf8"));
  assert.equal(stats.aws_keys.matchCount, 3);
});

test("does nothing and does not create a file when both lists are empty", () => {
  const userConfigDir = mkTmp("promptknight-stats-");
  recordPatternActivity([], [], userConfigDir);
  const statsPath = path.join(userConfigDir, "logs", "pattern-stats.json");
  assert.equal(fs.existsSync(statsPath), false);
});

test("sets owner-only permissions on the stats file", { skip: process.platform === "win32" }, () => {
  const userConfigDir = mkTmp("promptknight-stats-");
  recordPatternActivity([detection("aws_keys")], [], userConfigDir);
  const statsPath = path.join(userConfigDir, "logs", "pattern-stats.json");
  assert.equal(fs.statSync(statsPath).mode & 0o777, 0o600);
});

test("never throws and returns a warning when the destination is unwritable", () => {
  const userConfigDir = mkTmp("promptknight-stats-");
  // Make ".../logs" impossible to create by occupying its path with a file.
  fs.writeFileSync(path.join(userConfigDir, "logs"), "not a directory");
  const result = recordPatternActivity([detection("aws_keys")], [], userConfigDir);
  assert.ok(result.warning);
});
