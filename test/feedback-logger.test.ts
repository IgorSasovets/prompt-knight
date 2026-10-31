import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { logDetections, logFeedback, logOperationalEvents } from "../src/feedback-logger";
import { Config, Detection } from "../src/types";
import { Tier2Evidence } from "../src/tier2-ollama";

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function baseLoggingConfig(overrides: Partial<Config["logging"]> = {}): Config["logging"] {
  return {
    enabled: true,
    logDir: "~/.prompt-knight/logs",
    logFile: "detections.jsonl",
    redactValues: true,
    previewChars: 4,
    ...overrides,
  };
}

const detection: Detection = {
  category: "aws_keys",
  source: "tier1",
  patternId: "aws_keys",
  index: 10,
  length: 20,
  matchedText: "AKIAEXAMPLEEXAMPLE12",
};

test("writes a redacted preview, never the raw value", () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  const result = logDetections(baseLoggingConfig(), "block", [detection], homedir, userConfigDir);
  assert.equal(result.warning, undefined);

  const logPath = path.join(userConfigDir, "logs", "detections.jsonl");
  const lines = fs.readFileSync(logPath, "utf8").trim().split("\n");
  const entry = JSON.parse(lines[lines.length - 1]!);
  assert.equal(entry.category, "aws_keys");
  assert.equal(entry.mode, "block");
  assert.equal(entry.preview, "AKIA***");
  assert.ok(!JSON.stringify(entry).includes(detection.matchedText));
});

test("previewChars: 0 disables the preview entirely", () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  logDetections(baseLoggingConfig({ previewChars: 0 }), "block", [detection], homedir, userConfigDir);

  const logPath = path.join(userConfigDir, "logs", "detections.jsonl");
  const entry = JSON.parse(fs.readFileSync(logPath, "utf8").trim());
  assert.equal("preview" in entry, false);
  assert.equal("value" in entry, false);
});

test("redactValues: false writes the full matched value (explicit opt-out)", () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  logDetections(baseLoggingConfig({ redactValues: false }), "block", [detection], homedir, userConfigDir);

  const logPath = path.join(userConfigDir, "logs", "detections.jsonl");
  const entry = JSON.parse(fs.readFileSync(logPath, "utf8").trim());
  assert.equal(entry.value, detection.matchedText);
});

test("log directory and file get owner-only permissions", { skip: process.platform === "win32" }, () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  logDetections(baseLoggingConfig(), "block", [detection], homedir, userConfigDir);

  const logDir = path.join(userConfigDir, "logs");
  const logPath = path.join(logDir, "detections.jsonl");
  assert.equal(fs.statSync(logDir).mode & 0o777, 0o700);
  assert.equal(fs.statSync(logPath).mode & 0o777, 0o600);
});

test("re-chmods a pre-existing file/dir back to owner-only on every write", { skip: process.platform === "win32" }, () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  const logDir = path.join(userConfigDir, "logs");
  fs.mkdirSync(logDir, { recursive: true, mode: 0o755 });
  fs.writeFileSync(path.join(logDir, "detections.jsonl"), "", { mode: 0o644 });

  logDetections(baseLoggingConfig(), "block", [detection], homedir, userConfigDir);

  assert.equal(fs.statSync(logDir).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.join(logDir, "detections.jsonl")).mode & 0o777, 0o600);
});

test("an unwritable log destination fails open with a warning, never throws", () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  // Make ".prompt-knight" a file instead of a directory, so mkdir(.../logs) must fail.
  fs.writeFileSync(userConfigDir, "not a directory");

  const result = logDetections(baseLoggingConfig(), "block", [detection], homedir, userConfigDir);
  assert.ok(result.warning && result.warning.includes("unwritable"));
});

test("a logDir outside ~/.prompt-knight/ is refused and falls back to the default location", () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  const result = logDetections(
    baseLoggingConfig({ logDir: "/tmp/somewhere-else" }),
    "block",
    [detection],
    homedir,
    userConfigDir
  );
  assert.ok(result.warning && result.warning.includes("resolves outside"));

  const fallbackPath = path.join(userConfigDir, "logs", "detections.jsonl");
  assert.ok(fs.existsSync(fallbackPath));
});

test("logOperationalEvents records diagnostic events distinct from detections", () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  logOperationalEvents(baseLoggingConfig(), "pattern_load_error", ["skipped pattern X"], homedir, userConfigDir);

  const logPath = path.join(userConfigDir, "logs", "detections.jsonl");
  const entry = JSON.parse(fs.readFileSync(logPath, "utf8").trim());
  assert.equal(entry.event, "pattern_load_error");
  assert.equal(entry.message, "skipped pattern X");
});

function baseFeedbackConfig(overrides: Partial<Config["feedback"]> = {}): Config["feedback"] {
  return {
    enabled: true,
    suggestPatterns: true,
    autoExtendPatterns: false,
    minHitsForSuggestion: 3,
    evidencePreviewChars: 64,
    ...overrides,
  };
}

const evidence: Tier2Evidence = { category: "email", text: "someone@example.com", confidence: 0.9 };

test("logFeedback writes to a separate feedback.jsonl, truncated to evidencePreviewChars", () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  logFeedback(baseLoggingConfig(), baseFeedbackConfig({ evidencePreviewChars: 8 }), [evidence], homedir, userConfigDir);

  const feedbackPath = path.join(userConfigDir, "logs", "feedback.jsonl");
  const entry = JSON.parse(fs.readFileSync(feedbackPath, "utf8").trim());
  assert.equal(entry.category, "email");
  assert.equal(entry.evidencePreview, "someone@***");
  assert.ok(!fs.existsSync(path.join(userConfigDir, "logs", "detections.jsonl")));
});

test("logFeedback is a no-op when feedback.enabled is false", () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  logFeedback(baseLoggingConfig(), baseFeedbackConfig({ enabled: false }), [evidence], homedir, userConfigDir);

  const feedbackPath = path.join(userConfigDir, "logs", "feedback.jsonl");
  assert.equal(fs.existsSync(feedbackPath), false);
});

test("logFeedback with evidencePreviewChars: 0 writes nothing for that entry", () => {
  const homedir = mkTmp("promptknight-log-home-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  const result = logFeedback(
    baseLoggingConfig(),
    baseFeedbackConfig({ evidencePreviewChars: 0 }),
    [evidence],
    homedir,
    userConfigDir
  );
  assert.deepEqual(result, {});
  const feedbackPath = path.join(userConfigDir, "logs", "feedback.jsonl");
  assert.equal(fs.existsSync(feedbackPath), false);
});
