import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { spawnSync } from "node:child_process";

const scriptPath = path.join(__dirname, "..", "src", "scan-tool-output.js");
const FAKE_AWS_KEY = "AKIAEXAMPLEEXAMPLE12";

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function runHook(toolName: string, toolResponse: unknown, cwd: string, homedir: string): { status: number | null; stdout: string; stderr: string } {
  const payload = JSON.stringify({
    session_id: "test-session",
    cwd,
    permission_mode: "default",
    hook_event_name: "PostToolUse",
    tool_name: toolName,
    tool_response: toolResponse,
    tool_use_id: "toolu_test",
  });

  const result = spawnSync(process.execPath, [scriptPath], {
    input: payload,
    cwd,
    env: { ...process.env, HOME: homedir, USERPROFILE: homedir },
    encoding: "utf8",
  });

  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function readToolResponse(content: string) {
  return { type: "text", file: { filePath: "/tmp/sample.txt", content, numLines: 1, startLine: 1, totalLines: 1 } };
}

test("Read: a key in file content is redacted via updatedToolOutput, never left in the raw response (block mode)", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const { status, stdout } = runHook("Read", readToolResponse(`AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\n`), cwd, homedir);
  assert.equal(status, 0);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.decision, "block");
  assert.ok(!parsed.reason.includes(FAKE_AWS_KEY));
  const updated = parsed.hookSpecificOutput.updatedToolOutput;
  assert.ok(!JSON.stringify(updated).includes(FAKE_AWS_KEY), "the raw secret must not survive anywhere in updatedToolOutput");
  assert.ok(updated.file.content.includes("[REDACTED:aws_keys]"));
  // Sibling fields must be preserved exactly (D22 — a shape mismatch is a silent bypass).
  assert.equal(updated.file.filePath, "/tmp/sample.txt");
  assert.equal(updated.type, "text");
});

test("Read: clean content is allowed with no hookSpecificOutput at all", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const { status, stdout } = runHook("Read", readToolResponse("just some ordinary source code\n"), cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
});

test("Grep: matched content containing a key is redacted, mode/filenames preserved", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const toolResponse = { mode: "content", numFiles: 0, filenames: [], content: `2:AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}`, numLines: 1, totalLines: 1 };
  const { status, stdout } = runHook("Grep", toolResponse, cwd, homedir);
  assert.equal(status, 0);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.decision, "block");
  const updated = parsed.hookSpecificOutput.updatedToolOutput;
  assert.ok(!JSON.stringify(updated).includes(FAKE_AWS_KEY));
  assert.equal(updated.mode, "content");
  assert.deepEqual(updated.filenames, []);
});

test("Grep: files_with_matches mode has no raw content and is a no-op", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const { status, stdout } = runHook("Grep", { mode: "files_with_matches", numFiles: 1, filenames: ["a.txt"] }, cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
});

test("Bash: a key in stdout is redacted while stderr is left untouched", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const toolResponse = { stdout: `AWS_SECRET_ACCESS_KEY=${FAKE_AWS_KEY}`, stderr: "a harmless warning", interrupted: false, isImage: false, noOutputExpected: false };
  const { status, stdout } = runHook("Bash", toolResponse, cwd, homedir);
  assert.equal(status, 0);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.decision, "block");
  const updated = parsed.hookSpecificOutput.updatedToolOutput;
  assert.ok(!JSON.stringify(updated).includes(FAKE_AWS_KEY));
  assert.equal(updated.stderr, "a harmless warning");
  assert.equal(updated.interrupted, false);
});

test("warn mode: leaves tool_response unmodified but adds additionalContext, never raw value", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  fs.writeFileSync(path.join(cwd, ".prompt-knight.json"), JSON.stringify({ mode: "warn" }));
  const { status, stdout } = runHook("Read", readToolResponse(`key=${FAKE_AWS_KEY}`), cwd, homedir);
  assert.equal(status, 0);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.decision, undefined);
  assert.equal(parsed.hookSpecificOutput.updatedToolOutput, undefined);
  assert.ok(parsed.hookSpecificOutput.additionalContext.includes("aws_keys"));
  assert.ok(!parsed.hookSpecificOutput.additionalContext.includes(FAKE_AWS_KEY));
});

test("audit mode: allows silently but still logs the detection with channel/tool tags", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  fs.writeFileSync(path.join(cwd, ".prompt-knight.json"), JSON.stringify({ mode: "audit" }));
  const { status, stdout, stderr } = runHook("Read", readToolResponse(`key=${FAKE_AWS_KEY}`), cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
  assert.equal(stderr, "");

  const logPath = path.join(homedir, ".prompt-knight", "logs", "detections.jsonl");
  const entry = JSON.parse(fs.readFileSync(logPath, "utf8").trim());
  assert.equal(entry.category, "aws_keys");
  assert.equal(entry.channel, "tool_output");
  assert.equal(entry.tool, "Read");
});

test("toolOutput.enabled:false allows a secret-bearing read through untouched", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  fs.writeFileSync(path.join(cwd, ".prompt-knight.json"), JSON.stringify({ toolOutput: { enabled: false } }));
  const { status, stdout } = runHook("Read", readToolResponse(`key=${FAKE_AWS_KEY}`), cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
});

test("feedback.enabled: a tool-output detection feeds per-pattern stats, same as the prompt channel", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  fs.writeFileSync(path.join(cwd, ".prompt-knight.json"), JSON.stringify({ mode: "audit", feedback: { enabled: true } }));
  const { status } = runHook("Read", readToolResponse(`key=${FAKE_AWS_KEY}`), cwd, homedir);
  assert.equal(status, 0);

  const statsPath = path.join(homedir, ".prompt-knight", "logs", "pattern-stats.json");
  const stats = JSON.parse(fs.readFileSync(statsPath, "utf8"));
  assert.equal(stats.aws_keys.matchCount, 1);
});

test("an unsupported tool_name is a no-op allow", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const { status, stdout, stderr } = runHook("WebFetch", { body: `key=${FAKE_AWS_KEY}` }, cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
  assert.equal(stderr, "");
});
