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
// PostToolUse hook (T6.4/T6.5, REQ-TOOL-04..10, D19/D22/D23): closes OD2 by running
// Read/Grep/Bash content through the same Tier1/gitleaks/Tier2 pipeline that
// scan-prompt.ts already runs on prompt text, then redacting in place via
// `updatedToolOutput` before the content reaches the model.
//
// Critical constraint (verified empirically against a real Claude Code session,
// not assumed from docs — see .specs/promptknight/design.md D22): a top-level
// `decision:"block"` alone does NOT stop the original tool output from reaching the
// model; only `hookSpecificOutput.updatedToolOutput`, re-emitted in the tool's exact
// original shape, does. A shape mismatch is a silent DLP bypass, not a crash — so
// `tool-output-extract.ts`'s rebuild only ever overwrites the field it read.
//
// Each extracted field (Read's file content; Grep's matched content; Bash's stdout
// and stderr independently) is scanned and decided on its own — a clean stdout next
// to a leaking stderr should redact only the stderr, not blank the whole call — and
// the tool-level outcome is the highest-precedence field outcome (block > warn >
// allow), the same "escalate, never downgrade" spirit D9 already applies to Tier 2
// vs. Tier 1.
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const config_loader_1 = require("./config-loader");
const enforcement_1 = require("./enforcement");
const feedback_logger_1 = require("./feedback-logger");
const gitleaks_adapter_1 = require("./gitleaks-adapter");
const pattern_stats_1 = require("./pattern-stats");
const tier1_engine_1 = require("./tier1-engine");
const tool_output_extract_1 = require("./tool-output-extract");
const tier2_ollama_1 = require("./tier2-ollama");
const validation_1 = require("./validation");
function readStdin() {
    try {
        return fs.readFileSync(0, "utf8");
    }
    catch {
        return "";
    }
}
function emitAllow() {
    process.exitCode = 0;
}
function placeholderFor(category) {
    return `[REDACTED:${category}]`;
}
const FULL_FIELD_PLACEHOLDER = "[PromptKnight: content withheld — a possible secret was detected but could not be safely isolated for redaction]";
function buildReason(toolName, label, records, config) {
    const withDetections = records.filter((r) => r.detections.length > 0);
    const unresolvedOnly = records.filter((r) => r.detections.length === 0);
    const parts = [];
    if (withDetections.length > 0) {
        const categories = Array.from(new Set(withDetections.flatMap((r) => r.detections.map((d) => d.category))));
        const previews = withDetections
            .flatMap((r) => r.detections)
            .map((d) => (config.logging.redactValues ? (0, validation_1.redactPreview)(d.matchedText, config.logging.previewChars) : undefined))
            .filter((p) => p !== undefined);
        const previewText = previews.length > 0 ? ` (preview: ${previews.join(", ")})` : "";
        parts.push(`possible ${categories.join(", ")} detected${previewText}`);
    }
    if (unresolvedOnly.length > 0) {
        parts.push(`semantic analysis (Tier 2) could not complete for ${unresolvedOnly.map((r) => r.field).join(", ")}, and the configured mode fails closed when a check can't run`);
    }
    return `PromptKnight ${label} this ${toolName} output: ${parts.join("; ")}.`;
}
async function evaluateField(text, field, config, patterns, allowedRoots, workerScriptPath, homedir, userConfigDir, toolName) {
    const result = await (0, tier1_engine_1.scan)(text, patterns, {
        maxPromptBytes: config.maxPromptBytes,
        patternTimeoutMs: config.tier1.patternTimeoutMs,
        allowlist: config.tier1.allowlist,
        workerScriptPath,
    });
    let combinedDetections = result.detections;
    const allMatched = [...result.detections];
    const allSuppressed = [...result.suppressed];
    let tier2Evidence = [];
    if (result.timeouts.length > 0) {
        (0, feedback_logger_1.logOperationalEvents)(config.logging, "tool_output_pattern_timeout", result.timeouts, homedir, userConfigDir);
    }
    if (config.gitleaks.enabled) {
        const gitleaksResult = (0, gitleaks_adapter_1.scanWithGitleaks)(text, config.gitleaks, allowedRoots, config.maxPromptBytes);
        if (gitleaksResult.errors.length > 0) {
            (0, feedback_logger_1.logOperationalEvents)(config.logging, "tool_output_gitleaks_error", gitleaksResult.errors, homedir, userConfigDir);
        }
        const allowlistFiltered = gitleaksResult.detections.filter((d) => !(0, tier1_engine_1.isAllowlisted)(d.matchedText, config.tier1.allowlist));
        const allowlistSuppressed = gitleaksResult.detections.filter((d) => (0, tier1_engine_1.isAllowlisted)(d.matchedText, config.tier1.allowlist));
        allMatched.push(...allowlistFiltered);
        allSuppressed.push(...allowlistSuppressed);
        combinedDetections = (0, tier1_engine_1.dedupeDetections)([...combinedDetections, ...allowlistFiltered]);
    }
    let tier2RequestFailed = false;
    if (config.tier2.enabled) {
        if (!(0, tier2_ollama_1.isLocalHostname)(config.tier2.ollamaUrl) && config.tier2.allowNonLocal) {
            (0, feedback_logger_1.logOperationalEvents)(config.logging, "tool_output_tier2_nonlocal_warning", [`tier2.ollamaUrl "${config.tier2.ollamaUrl}" is non-local and allowNonLocal is true — ${toolName} output is leaving this host.`], homedir, userConfigDir);
        }
        const tier2Outcome = await (0, tier2_ollama_1.callOllama)(text, config.tier2, config.maxPromptBytes);
        if (tier2Outcome.kind === "skipped") {
            (0, feedback_logger_1.logOperationalEvents)(config.logging, "tool_output_tier2_skipped", [tier2Outcome.reason], homedir, userConfigDir);
        }
        else if (tier2Outcome.kind === "failed") {
            tier2RequestFailed = true;
            (0, feedback_logger_1.logOperationalEvents)(config.logging, "tool_output_tier2_failed", [tier2Outcome.reason], homedir, userConfigDir);
        }
        else {
            tier2Evidence = tier2Outcome.evidence;
            if (tier2Outcome.detections.length > 0) {
                allMatched.push(...tier2Outcome.detections);
                combinedDetections = (0, tier1_engine_1.dedupeDetections)([...combinedDetections, ...tier2Outcome.detections]);
            }
        }
    }
    const fieldDecision = (0, enforcement_1.decide)(config.mode, combinedDetections, tier2RequestFailed);
    return { field, text, detections: combinedDetections, decision: fieldDecision, allMatched, allSuppressed, tier2Evidence };
}
function highestPrecedence(records) {
    if (records.some((r) => r.decision === "block"))
        return "block";
    if (records.some((r) => r.decision === "warn"))
        return "warn";
    return "allow";
}
async function main() {
    const homedir = os.homedir();
    const pluginRoot = path.resolve(__dirname, "..", "..");
    const workerScriptPath = path.join(__dirname, "pattern-worker.js");
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
    if (toolName !== "Read" && toolName !== "Grep" && toolName !== "Bash") {
        emitAllow();
        return;
    }
    const { config, userConfigDir, errors: configErrors } = (0, config_loader_1.loadConfig)(pluginRoot, projectRoot, homedir);
    const allowedRoots = [pluginRoot, userConfigDir, projectRoot];
    if (!config.toolOutput.enabled || !config.toolOutput.tools.includes(toolName)) {
        emitAllow();
        return;
    }
    const fields = (0, tool_output_extract_1.extractScannableFields)(toolName, payload.tool_response);
    if (fields.length === 0) {
        emitAllow();
        return;
    }
    try {
        const { patterns, loadErrors } = (0, tier1_engine_1.loadPatterns)(pluginRoot, config.tier1, allowedRoots);
        if (configErrors.length > 0) {
            (0, feedback_logger_1.logOperationalEvents)(config.logging, "tool_output_config_error", configErrors, homedir, userConfigDir);
        }
        if (loadErrors.length > 0) {
            (0, feedback_logger_1.logOperationalEvents)(config.logging, "tool_output_pattern_load_error", loadErrors, homedir, userConfigDir);
        }
        const records = [];
        for (const f of fields) {
            records.push(await evaluateField(f.text, f.field, config, patterns, allowedRoots, workerScriptPath, homedir, userConfigDir, toolName));
        }
        for (const record of records) {
            if (record.detections.length > 0) {
                (0, feedback_logger_1.logDetections)(config.logging, config.mode, record.detections, homedir, userConfigDir, {
                    channel: "tool_output",
                    tool: toolName,
                });
            }
            if (config.feedback.enabled) {
                const statsWarning = (0, pattern_stats_1.recordPatternActivity)(record.allMatched, record.allSuppressed, userConfigDir).warning;
                if (statsWarning)
                    process.stderr.write(`${statsWarning}\n`);
                const feedbackWarning = (0, feedback_logger_1.logFeedback)(config.logging, config.feedback, record.tier2Evidence, homedir, userConfigDir).warning;
                if (feedbackWarning)
                    process.stderr.write(`${feedbackWarning}\n`);
            }
        }
        const overall = highestPrecedence(records);
        if (overall === "block") {
            const blockRecords = records.filter((r) => r.decision === "block");
            const replacements = new Map();
            for (const record of blockRecords) {
                if (record.detections.length > 0) {
                    const redaction = (0, validation_1.redactByOffsets)(record.text, record.detections, placeholderFor);
                    replacements.set(record.field, redaction.fullyVerifiable ? redaction.text : FULL_FIELD_PLACEHOLDER);
                }
                else {
                    // decide() only returns "block" with zero detections on unresolved risk
                    // (a Tier 2 request failure) — fail closed on the whole field (D23).
                    replacements.set(record.field, FULL_FIELD_PLACEHOLDER);
                }
            }
            const updatedToolOutput = (0, tool_output_extract_1.rebuildToolResponse)(payload.tool_response, replacements);
            const reason = buildReason(toolName, "blocked", blockRecords, config);
            process.stdout.write(JSON.stringify({
                decision: "block",
                reason,
                hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput },
            }));
            process.exitCode = 0;
            return;
        }
        if (overall === "warn") {
            const warnRecords = records.filter((r) => r.decision === "warn");
            const additionalContext = buildReason(toolName, "flagged", warnRecords, config);
            process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext } }));
            process.exitCode = 0;
            return;
        }
        emitAllow();
    }
    finally {
        (0, tier1_engine_1.shutdownPatternWorker)();
    }
}
void main();
