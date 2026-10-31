import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { spawnSync } from "node:child_process";
import {
  appendCustomPattern,
  purgeFeedbackRecords,
  readApprovedSignatures,
  readFeedbackRecords,
  writeApprovedSignatures,
} from "../src/review-patterns";
import { normalizeShape } from "../src/pattern-suggester";

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function feedbackLine(category: string, evidencePreview: string, confidence = 0.9): string {
  return JSON.stringify({ timestamp: new Date().toISOString(), category, confidence, evidencePreview });
}

test("readFeedbackRecords returns [] when the file doesn't exist", () => {
  const dir = mkTmp("promptknight-review-");
  assert.deepEqual(readFeedbackRecords(path.join(dir, "feedback.jsonl")), []);
});

test("readFeedbackRecords parses valid lines and skips malformed ones", () => {
  const dir = mkTmp("promptknight-review-");
  const logPath = path.join(dir, "feedback.jsonl");
  fs.writeFileSync(logPath, `${feedbackLine("email", "a@b.com")}\nnot json\n${feedbackLine("email", "c@d.com")}\n`);

  const records = readFeedbackRecords(logPath);
  assert.equal(records.length, 2);
  assert.equal(records[0]!.category, "email");
});

test("readApprovedSignatures returns an empty set when the state file doesn't exist", () => {
  const dir = mkTmp("promptknight-review-");
  assert.deepEqual(readApprovedSignatures(path.join(dir, "state.json")), new Set());
});

test("writeApprovedSignatures then readApprovedSignatures round-trips", () => {
  const dir = mkTmp("promptknight-review-");
  const statePath = path.join(dir, "state.json");
  writeApprovedSignatures(statePath, new Set(["email::A@A.A"]));
  assert.deepEqual(readApprovedSignatures(statePath), new Set(["email::A@A.A"]));
});

test("purgeFeedbackRecords removes only matching-signature lines", () => {
  const dir = mkTmp("promptknight-review-");
  const logPath = path.join(dir, "feedback.jsonl");
  fs.writeFileSync(logPath, `${feedbackLine("email", "a@b.com")}\n${feedbackLine("phone_number", "555-1234")}\n`);

  const emailSignature = `email::${normalizeShape("a@b.com")}`;
  purgeFeedbackRecords(logPath, new Set([emailSignature]));

  const remaining = readFeedbackRecords(logPath);
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0]!.category, "phone_number");
});

test("appendCustomPattern validates (ReDoS + compile) before writing", () => {
  const dir = mkTmp("promptknight-review-");
  const customPath = path.join(dir, "custom.json");
  fs.writeFileSync(customPath, "[]");

  const safe = appendCustomPattern(customPath, { id: "safe-1", category: "safe", regex: "[A-Za-z]+@[A-Za-z]+\\.[A-Za-z]+" });
  assert.equal(safe.ok, true);

  const unsafe = appendCustomPattern(customPath, { id: "unsafe-1", category: "unsafe", regex: "(a+)+$" });
  assert.equal(unsafe.ok, false);

  const written = JSON.parse(fs.readFileSync(customPath, "utf8"));
  assert.equal(written.length, 1);
  assert.equal(written[0].id, "safe-1");
});

test("appendCustomPattern rejects a pattern that fails to compile", () => {
  const dir = mkTmp("promptknight-review-");
  const customPath = path.join(dir, "custom.json");
  fs.writeFileSync(customPath, "[]");
  const result = appendCustomPattern(customPath, { id: "bad", category: "bad", regex: "a(" });
  assert.equal(result.ok, false);
});

test("appendCustomPattern creates the file if it doesn't exist yet", () => {
  const dir = mkTmp("promptknight-review-");
  const customPath = path.join(dir, "custom.json");
  const result = appendCustomPattern(customPath, { id: "new-1", category: "new", regex: "[A-Za-z]+" });
  assert.equal(result.ok, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(customPath, "utf8")).map((p: { id: string }) => p.id), ["new-1"]);
});

test("end-to-end CLI: approve one suggestion via scripted stdin", () => {
  const homedir = mkTmp("promptknight-review-e2e-home-");
  const projectRoot = mkTmp("promptknight-review-e2e-project-");
  const userConfigDir = path.join(homedir, ".prompt-knight");
  const logDir = path.join(userConfigDir, "logs");
  fs.mkdirSync(logDir, { recursive: true });

  const lines = [feedbackLine("email", "a@b.com"), feedbackLine("email", "c@d.com"), feedbackLine("email", "e@f.com")];
  fs.writeFileSync(path.join(logDir, "feedback.jsonl"), `${lines.join("\n")}\n`);

  // Point customPatternsFile at an isolated temp file (within the sandboxed
  // projectRoot) so this test never touches the real repo's patterns/custom.json.
  const isolatedCustomPatternsPath = path.join(projectRoot, "custom.json");
  fs.writeFileSync(
    path.join(projectRoot, ".prompt-knight.json"),
    JSON.stringify({ feedback: { minHitsForSuggestion: 3 }, tier1: { customPatternsFile: isolatedCustomPatternsPath } })
  );

  const cliPath = path.join(__dirname, "..", "src", "review-patterns.js");
  const result = spawnSync(process.execPath, [cliPath], {
    input: "a\n",
    cwd: projectRoot,
    env: { ...process.env, HOME: homedir, USERPROFILE: homedir },
    encoding: "utf8",
  });

  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.includes("Approved 1, skipped 0."));

  const written = JSON.parse(fs.readFileSync(isolatedCustomPatternsPath, "utf8"));
  assert.equal(written.length, 1);
  assert.equal(written[0].category, "email");

  const remainingFeedback = readFeedbackRecords(path.join(logDir, "feedback.jsonl"));
  assert.equal(remainingFeedback.length, 0); // approved suggestion's evidence was purged

  const state = readApprovedSignatures(path.join(logDir, "pattern-suggestions-state.json"));
  assert.equal(state.size, 1);
});
