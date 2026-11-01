import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { spawnSync } from "node:child_process";

const scriptPath = path.join(__dirname, "..", "src", "scan-tool-input.js");

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function runHook(toolName: string, toolInput: unknown, cwd: string, homedir: string): { status: number | null; stdout: string; stderr: string } {
  const payload = JSON.stringify({
    session_id: "test-session",
    cwd,
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name: toolName,
    tool_input: toolInput,
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

test("Read targeting a denied path (.env) is denied in block mode", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const { status, stdout } = runHook("Read", { file_path: path.join(cwd, ".env") }, cwd, homedir);
  assert.equal(status, 0);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(parsed.hookSpecificOutput.permissionDecision, "deny");
  assert.ok(parsed.hookSpecificOutput.permissionDecisionReason.includes(".env"));
});

test("Read targeting an ordinary file is allowed", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const { status, stdout } = runHook("Read", { file_path: path.join(cwd, "src", "index.ts") }, cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
});

test("Grep targeting a .ssh/* path is denied in block mode", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const { status, stdout } = runHook("Grep", { pattern: "key", path: path.join(cwd, ".ssh", "id_rsa") }, cwd, homedir);
  assert.equal(status, 0);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.hookSpecificOutput.permissionDecision, "deny");
});

test("warn mode never denies — defers entirely to the PostToolUse content scan", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  fs.writeFileSync(path.join(cwd, ".prompt-knight.json"), JSON.stringify({ mode: "warn" }));
  const { status, stdout } = runHook("Read", { file_path: path.join(cwd, ".env") }, cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
});

test("Bash is never denied by this hook (D25) regardless of its command text", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  const { status, stdout } = runHook("Bash", { command: "cat .env", description: "read env" }, cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
});

test("toolOutput.enabled:false disables deny-by-path entirely", () => {
  const homedir = mkTmp("promptknight-e2e-home-");
  const cwd = mkTmp("promptknight-e2e-project-");
  fs.writeFileSync(path.join(cwd, ".prompt-knight.json"), JSON.stringify({ toolOutput: { enabled: false } }));
  const { status, stdout } = runHook("Read", { file_path: path.join(cwd, ".env") }, cwd, homedir);
  assert.equal(status, 0);
  assert.equal(stdout, "");
});
