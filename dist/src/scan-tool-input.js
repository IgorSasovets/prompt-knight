#!/usr/bin/env node
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
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
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const config_loader_1 = require("./config-loader");
const glob_match_1 = require("./glob-match");
const validation_1 = require("./validation");
function readStdin() {
    try {
        return fs.readFileSync(0, "utf8");
    }
    catch {
        return "";
    }
}
function extractCandidatePath(toolName, toolInput) {
    if (!(0, validation_1.isPlainObject)(toolInput))
        return null;
    if (toolName === "Read" && typeof toolInput.file_path === "string" && toolInput.file_path.length > 0) {
        return toolInput.file_path;
    }
    if (toolName === "Grep" && typeof toolInput.path === "string" && toolInput.path.length > 0) {
        return toolInput.path;
    }
    return null;
}
function emitAllow() {
    process.exitCode = 0;
}
function emitDeny(pattern) {
    process.stdout.write(JSON.stringify({
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: `PromptKnight blocked this read: the target path matches the configured sensitive-file pattern "${pattern}".`,
        },
    }));
    process.exitCode = 0;
}
function main() {
    try {
        const homedir = os.homedir();
        const pluginRoot = path.resolve(__dirname, "..", "..");
        const raw = readStdin();
        let payload = {};
        try {
            payload = raw.trim() ? JSON.parse(raw) : {};
        }
        catch {
            payload = {};
        }
        const toolName = typeof payload.tool_name === "string" ? payload.tool_name : "";
        const projectRoot = typeof payload.cwd === "string" ? payload.cwd : process.cwd();
        if (toolName !== "Read" && toolName !== "Grep") {
            emitAllow();
            return;
        }
        const { config } = (0, config_loader_1.loadConfig)(pluginRoot, projectRoot, homedir);
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
        const matched = (0, glob_match_1.matchesAnyDenyPattern)(resolvedPath, config.toolOutput.denyPathPatterns);
        if (matched) {
            emitDeny(matched);
            return;
        }
        emitAllow();
    }
    catch {
        // Fail open — this hook is defense-in-depth only (see module header).
        emitAllow();
    }
}
main();
