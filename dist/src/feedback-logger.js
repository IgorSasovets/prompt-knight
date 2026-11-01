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
exports.logDetections = logDetections;
exports.logFeedback = logFeedback;
exports.logOperationalEvents = logOperationalEvents;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const validation_1 = require("./validation");
const config_loader_1 = require("./config-loader");
const FEEDBACK_LOG_FILE = "feedback.jsonl";
function resolveLogDir(loggingConfig, homedir, userConfigDir, sandboxErrors) {
    const expandedDir = (0, validation_1.expandHome)(loggingConfig.logDir, homedir);
    const resolvedDir = (0, config_loader_1.resolveSandboxedPath)(expandedDir, homedir, [userConfigDir], "logging.logDir", sandboxErrors);
    if (!resolvedDir) {
        sandboxErrors.push(`logging.logDir "${loggingConfig.logDir}" resolves outside ~/.prompt-knight/; using the default log directory instead.`);
    }
    return resolvedDir ?? path.join(userConfigDir, "logs");
}
function resolveLogPath(loggingConfig, homedir, userConfigDir, sandboxErrors) {
    return path.join(resolveLogDir(loggingConfig, homedir, userConfigDir, sandboxErrors), loggingConfig.logFile);
}
/**
 * Appends pre-built JSON lines to the audit log. Creates the log directory with 0700
 * and the log file with 0600, re-chmod'ing both on every write so the invariant holds
 * even if either pre-existed with looser permissions (REQ-LOG-03, D12). Never throws
 * into the enforcement path: any failure becomes a warning (REQ-LOG-05).
 */
function appendLines(logPath, lines) {
    if (lines.length === 0)
        return {};
    try {
        fs.mkdirSync(path.dirname(logPath), { recursive: true, mode: 0o700 });
        fs.chmodSync(path.dirname(logPath), 0o700);
        const fd = fs.openSync(logPath, "a", 0o600);
        try {
            fs.chmodSync(logPath, 0o600);
            fs.writeSync(fd, `${lines.join("\n")}\n`);
        }
        finally {
            fs.closeSync(fd);
        }
    }
    catch (err) {
        return { warning: `PromptKnight: audit log unwritable, continuing without logging (${err.message})` };
    }
    return {};
}
/** Appends one JSON line per detection to the audit log (REQ-LOG-01/02, REQ-TOOL-10). */
function logDetections(loggingConfig, mode, detections, homedir, userConfigDir, tag) {
    if (!loggingConfig.enabled || detections.length === 0)
        return {};
    const sandboxErrors = [];
    const logPath = resolveLogPath(loggingConfig, homedir, userConfigDir, sandboxErrors);
    const timestamp = new Date().toISOString();
    const lines = detections.map((d) => {
        const entry = {
            timestamp,
            mode,
            category: d.category,
            location: { index: d.index, length: d.length },
        };
        if (tag?.channel !== undefined)
            entry.channel = tag.channel;
        if (tag?.tool !== undefined)
            entry.tool = tag.tool;
        if (loggingConfig.redactValues) {
            const preview = (0, validation_1.redactPreview)(d.matchedText, loggingConfig.previewChars);
            if (preview !== undefined)
                entry.preview = preview;
        }
        else {
            // User has explicitly opted out of redaction — their own risk, not the default.
            entry.value = d.matchedText;
        }
        return JSON.stringify(entry);
    });
    const writeResult = appendLines(logPath, lines);
    const warnings = [...sandboxErrors, ...(writeResult.warning ? [writeResult.warning] : [])];
    return warnings.length > 0 ? { warning: warnings.join(" ") } : {};
}
/**
 * Appends Tier 2 evidence excerpts to a **separate** opt-in log (`feedback.jsonl`,
 * not `detections.jsonl`) for `review-patterns.ts` to mine (REQ-SI-01). The excerpt is
 * truncated via `redactPreview()`, using `feedback.evidencePreviewChars` (default 64)
 * rather than the much shorter `logging.previewChars` (default 4) — that value is
 * tuned for human-readable audit-log debugging, not for deriving a structural regex —
 * but it is still bounded/truncated, never the raw value. Only ever called when
 * `feedback.enabled` is true; this function also checks it defensively itself.
 */
function logFeedback(loggingConfig, feedbackConfig, evidence, homedir, userConfigDir) {
    if (!feedbackConfig.enabled || evidence.length === 0)
        return {};
    const sandboxErrors = [];
    const logDir = resolveLogDir(loggingConfig, homedir, userConfigDir, sandboxErrors);
    const logPath = path.join(logDir, FEEDBACK_LOG_FILE);
    const timestamp = new Date().toISOString();
    const lines = evidence
        .map((e) => {
        const preview = (0, validation_1.redactPreview)(e.text, feedbackConfig.evidencePreviewChars);
        if (preview === undefined)
            return null;
        return JSON.stringify({ timestamp, category: e.category, confidence: e.confidence, evidencePreview: preview });
    })
        .filter((line) => line !== null);
    const writeResult = appendLines(logPath, lines);
    const warnings = [...sandboxErrors, ...(writeResult.warning ? [writeResult.warning] : [])];
    return warnings.length > 0 ? { warning: warnings.join(" ") } : {};
}
/**
 * Appends operational diagnostic events (config errors, pattern-load errors,
 * pattern-timeout events — REQ-CFG-04, REQ-T1-05, REQ-T1-07) to the same audit log,
 * distinguished from detection entries by an "event" field instead of "category".
 */
function logOperationalEvents(loggingConfig, event, messages, homedir, userConfigDir) {
    if (!loggingConfig.enabled || messages.length === 0)
        return {};
    const sandboxErrors = [];
    const logPath = resolveLogPath(loggingConfig, homedir, userConfigDir, sandboxErrors);
    const timestamp = new Date().toISOString();
    const lines = messages.map((message) => JSON.stringify({ timestamp, event, message }));
    const writeResult = appendLines(logPath, lines);
    const warnings = [...sandboxErrors, ...(writeResult.warning ? [writeResult.warning] : [])];
    return warnings.length > 0 ? { warning: warnings.join(" ") } : {};
}
