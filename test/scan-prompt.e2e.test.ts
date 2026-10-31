import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { spawnSync } from "node:child_process";

const scriptPath = path.join(__dirname, "..", "src", "scan-prompt.js");

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function runHook(promptText: string, cwd: string, homedir: string): { status: number | null; stdout: string; stderr: string } {
  const payload = JSON.stringify({
    session_id: "test-session",
    transcript_path: path.join(cwd, "transcript.jsonl"),
    cwd,
    permission_mode: "default",
    hook_event_name: "UserPromptSubmit",
    prompt: promptText,
  });

  const result = spawnSync(process.execPath, [scriptPath], {
    input: payload,
    cwd,
    env: { ...process.env, HOME: homedir, USERPROFILE: homedir },
    encoding: "utf8",
  });

  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

test("a clean prompt is allowed (exit 0, no output)", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const { status, stdout, stderr } = runHook("please refactor the login handler", cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
  assert.equal(stderr, "");
});

test("a prompt containing a fake AWS key is blocked (exit 2) without leaking the raw value", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const fakeKey = "AKIAABCDEFGHIJKLMNOP";
  const { status, stderr } = runHook(`here is my key ${fakeKey} please use it`, cwd, homedir);
  assert.equal(status, 2);
  assert.ok(stderr.includes("aws_keys"));
  assert.ok(!stderr.includes(fakeKey));
});

test("warn mode allows the prompt but emits a systemMessage", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  fs.writeFileSync(path.join(cwd, ".prompt-knight.json"), JSON.stringify({ mode: "warn" }));

  const fakeKey = "AKIAABCDEFGHIJKLMNOP";
  const { status, stdout } = runHook(`here is my key ${fakeKey} please use it`, cwd, homedir);
  assert.equal(status, 0);
  const parsed = JSON.parse(stdout);
  assert.ok(typeof parsed.systemMessage === "string" && parsed.systemMessage.includes("aws_keys"));
  assert.ok(!parsed.systemMessage.includes(fakeKey));
});

test("audit mode allows the prompt silently while still logging the detection", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  fs.writeFileSync(path.join(cwd, ".prompt-knight.json"), JSON.stringify({ mode: "audit" }));

  const fakeKey = "AKIAABCDEFGHIJKLMNOP";
  const { status, stdout, stderr } = runHook(`here is my key ${fakeKey} please use it`, cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
  assert.equal(stderr, "");

  const logPath = path.join(homedir, ".prompt-knight", "logs", "detections.jsonl");
  const entry = JSON.parse(fs.readFileSync(logPath, "utf8").trim());
  assert.equal(entry.category, "aws_keys");
});

test("an empty prompt is a no-op allow", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const { status, stdout, stderr } = runHook("", cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
  assert.equal(stderr, "");
});
