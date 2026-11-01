#!/usr/bin/env node
// PreToolUse hook (T6.2, REQ-TOOL-01/02, D19/D20/D25): a cheap, deterministic
// defense-in-depth pre-filter that denies a Read/Grep call outright when its target
// path matches a configured sensitive-file pattern. Deliberately narrow in scope:
//
// - Only Read/Grep (D25) — Bash's tool_input.command is a free-form shell string,
//   not a path, and reliably parsing one out of it is fragile/out of scope. Bash is
//   still covered by the PostToolUse content scan in scan-tool-output.ts.
// - Only denies in block mode (D20) — deny is binary, and warn/audit modes defer
//   entirely to the PostToolUse content scan rather than inventing a second,
//   independent mode-semantics implementation here.
// - Any internal failure here fails open (exit 0, non-blocking): this layer is pure
//   optimization/defense-in-depth, never the enforcement boundary. PostToolUse is
//   the real backstop, so a crash here must never be treated as a bypass.
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { loadConfig } from "./config-loader";
import { matchesAnyDenyPattern } from "./glob-match";
import { isPlainObject } from "./validation";

interface HookPayload {
  tool_name?: unknown;
  tool_input?: unknown;
  cwd?: unknown;
}

function readStdin(): string {
  try {
    return fs.readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function extractCandidatePath(toolName: string, toolInput: unknown): string | null {
  if (!isPlainObject(toolInput)) return null;
  if (toolName === "Read" && typeof toolInput.file_path === "string" && toolInput.file_path.length > 0) {
    return toolInput.file_path;
  }
  if (toolName === "Grep" && typeof toolInput.path === "string" && toolInput.path.length > 0) {
    return toolInput.path;
  }
  return null;
}

function emitAllow(): void {
  process.exitCode = 0;
}

function emitDeny(pattern: string): void {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `PromptKnight blocked this read: the target path matches the configured sensitive-file pattern "${pattern}".`,
      },
    })
  );
  process.exitCode = 0;
}

function main(): void {
  try {
    const homedir = os.homedir();
    const pluginRoot = path.resolve(__dirname, "..", "..");

    const raw = readStdin();
    let payload: HookPayload = {};
    try {
      payload = raw.trim() ? JSON.parse(raw) : {};
    } catch {
      payload = {};
    }

    const toolName = typeof payload.tool_name === "string" ? payload.tool_name : "";
    const projectRoot = typeof payload.cwd === "string" ? payload.cwd : process.cwd();

    if (toolName !== "Read" && toolName !== "Grep") {
      emitAllow();
      return;
    }

    const { config } = loadConfig(pluginRoot, projectRoot, homedir);
    if (!config.toolOutput.enabled || config.mode !== "block") {
      emitAllow();
      return;
    }

    const candidatePath = extractCandidatePath(toolName, payload.tool_input);
    if (!candidatePath) {
      emitAllow();
      return;
    }

    const resolvedPath = path.resolve(projectRoot, candidatePath);
    const matched = matchesAnyDenyPattern(resolvedPath, config.toolOutput.denyPathPatterns);
    if (matched) {
      emitDeny(matched);
      return;
    }

    emitAllow();
  } catch {
    // Fail open — this hook is defense-in-depth only (see module header).
    emitAllow();
  }
}

main();
