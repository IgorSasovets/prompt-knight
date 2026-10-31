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
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const config_loader_1 = require("./config-loader");
const enforcement_1 = require("./enforcement");
const feedback_logger_1 = require("./feedback-logger");
const gitleaks_adapter_1 = require("./gitleaks-adapter");
const pattern_stats_1 = require("./pattern-stats");
const tier1_engine_1 = require("./tier1-engine");
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
function emitWarn(message) {
    process.stdout.write(JSON.stringify({ systemMessage: message }));
    process.exitCode = 0;
}
function emitBlock(reason) {
    process.stderr.write(reason);
    process.exitCode = 2;
}
function summarizeDetections(mode, categories, previews) {
    const uniqueCategories = Array.from(new Set(categories));
    const label = mode === "block" ? "blocked" : "flagged";
    const previewText = previews.some((p) => p !== undefined)
        ? ` (preview: ${previews.filter((p) => p !== undefined).join(", ")})`
        : "";
    return `PromptKnight ${label} this prompt: possible ${uniqueCategories.join(", ")} detected${previewText}.`;
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
    const prompt = typeof payload.prompt === "string" ? payload.prompt : "";
    const projectRoot = typeof payload.cwd === "string" ? payload.cwd : process.cwd();
    if (prompt.length === 0) {
        emitAllow();
        return;
    }
    const { config, userConfigDir, errors: configErrors } = (0, config_loader_1.loadConfig)(pluginRoot, projectRoot, homedir);
    const allowedRoots = [pluginRoot, userConfigDir, projectRoot];
    try {
        const { patterns, loadErrors } = (0, tier1_engine_1.loadPatterns)(pluginRoot, config.tier1, allowedRoots);
        const result = await (0, tier1_engine_1.scan)(prompt, patterns, {
            maxPromptBytes: config.maxPromptBytes,
            patternTimeoutMs: config.tier1.patternTimeoutMs,
            allowlist: config.tier1.allowlist,
            workerScriptPath,
        });
        let combinedDetections = result.detections;
        const allMatched = [...result.detections];
        const allSuppressed = [...result.suppressed];
        let tier2Evidence = [];
        if (config.gitleaks.enabled) {
            const gitleaksResult = (0, gitleaks_adapter_1.scanWithGitleaks)(prompt, config.gitleaks, allowedRoots, config.maxPromptBytes);
            if (gitleaksResult.errors.length > 0) {
                (0, feedback_logger_1.logOperationalEvents)(config.logging, "gitleaks_error", gitleaksResult.errors, homedir, userConfigDir);
            }
            const allowlistFiltered = gitleaksResult.detections.filter((d) => !(0, tier1_engine_1.isAllowlisted)(d.matchedText, config.tier1.allowlist));
            const allowlistSuppressed = gitleaksResult.detections.filter((d) => (0, tier1_engine_1.isAllowlisted)(d.matchedText, config.tier1.allowlist));
            allMatched.push(...allowlistFiltered);
            allSuppressed.push(...allowlistSuppressed);
            // Tier1 first so its more specific category name wins on a duplicate secret value.
            combinedDetections = (0, tier1_engine_1.dedupeDetections)([...combinedDetections, ...allowlistFiltered]);
        }
        let tier2RequestFailed = false;
        if (config.tier2.enabled) {
            if (!(0, tier2_ollama_1.isLocalHostname)(config.tier2.ollamaUrl) && config.tier2.allowNonLocal) {
                (0, feedback_logger_1.logOperationalEvents)(config.logging, "tier2_nonlocal_warning", [`tier2.ollamaUrl "${config.tier2.ollamaUrl}" is non-local and allowNonLocal is true — prompt content is leaving this host.`], homedir, userConfigDir);
            }
            const tier2Outcome = await (0, tier2_ollama_1.callOllama)(prompt, config.tier2, config.maxPromptBytes);
            if (tier2Outcome.kind === "skipped") {
                (0, feedback_logger_1.logOperationalEvents)(config.logging, "tier2_skipped", [tier2Outcome.reason], homedir, userConfigDir);
            }
            else if (tier2Outcome.kind === "failed") {
                tier2RequestFailed = true;
                (0, feedback_logger_1.logOperationalEvents)(config.logging, "tier2_failed", [tier2Outcome.reason], homedir, userConfigDir);
            }
            else {
                tier2Evidence = tier2Outcome.evidence;
                if (tier2Outcome.detections.length > 0) {
                    allMatched.push(...tier2Outcome.detections);
                    // Concatenated last: Tier 2 can only add detections, never remove tier1/gitleaks
                    // ones (D9, REQ-T2-03) — escalate-only falls out of this ordering for free.
                    combinedDetections = (0, tier1_engine_1.dedupeDetections)([...combinedDetections, ...tier2Outcome.detections]);
                }
            }
        }
        if (config.feedback.enabled) {
            const statsWarning = (0, pattern_stats_1.recordPatternActivity)(allMatched, allSuppressed, userConfigDir).warning;
            if (statsWarning)
                process.stderr.write(`${statsWarning}\n`);
            const feedbackWarning = (0, feedback_logger_1.logFeedback)(config.logging, config.feedback, tier2Evidence, homedir, userConfigDir).warning;
            if (feedbackWarning)
                process.stderr.write(`${feedbackWarning}\n`);
        }
        if (configErrors.length > 0) {
            (0, feedback_logger_1.logOperationalEvents)(config.logging, "config_error", configErrors, homedir, userConfigDir);
        }
        if (loadErrors.length > 0) {
            (0, feedback_logger_1.logOperationalEvents)(config.logging, "pattern_load_error", loadErrors, homedir, userConfigDir);
        }
        if (result.timeouts.length > 0) {
            (0, feedback_logger_1.logOperationalEvents)(config.logging, "pattern_timeout", result.timeouts, homedir, userConfigDir);
        }
        const logResult = (0, feedback_logger_1.logDetections)(config.logging, config.mode, combinedDetections, homedir, userConfigDir);
        if (logResult.warning) {
            process.stderr.write(`${logResult.warning}\n`);
        }
        const decision = (0, enforcement_1.decide)(config.mode, combinedDetections, tier2RequestFailed);
        if (decision === "block" || decision === "warn") {
            const message = combinedDetections.length === 0
                ? "PromptKnight could not complete semantic analysis (Tier 2) for this prompt, and the configured mode fails closed when a check can't run."
                : summarizeDetections(config.mode, combinedDetections.map((d) => d.category), combinedDetections.map((d) => config.logging.redactValues ? (0, validation_1.redactPreview)(d.matchedText, config.logging.previewChars) : undefined));
            if (decision === "block") {
                emitBlock(message);
            }
            else {
                emitWarn(message);
            }
        }
        else {
            emitAllow();
        }
    }
    catch (err) {
        const decision = (0, enforcement_1.decide)(config.mode, [], true);
        const message = (0, validation_1.sanitizeErrorForUser)(err);
        if (decision === "block") {
            emitBlock(message);
        }
        else {
            emitWarn(message);
        }
    }
    finally {
        (0, tier1_engine_1.shutdownPatternWorker)();
    }
}
void main();
