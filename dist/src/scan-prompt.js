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
const tier1_engine_1 = require("./tier1-engine");
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
        if (config.gitleaks.enabled) {
            const gitleaksResult = (0, gitleaks_adapter_1.scanWithGitleaks)(prompt, config.gitleaks, allowedRoots);
            if (gitleaksResult.errors.length > 0) {
                (0, feedback_logger_1.logOperationalEvents)(config.logging, "gitleaks_error", gitleaksResult.errors, homedir, userConfigDir);
            }
            const allowlistFiltered = gitleaksResult.detections.filter((d) => !(0, tier1_engine_1.isAllowlisted)(d.matchedText, config.tier1.allowlist));
            // Tier1 first so its more specific category name wins on a duplicate secret value.
            combinedDetections = (0, tier1_engine_1.dedupeDetections)([...result.detections, ...allowlistFiltered]);
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
        const decision = (0, enforcement_1.decide)(config.mode, combinedDetections, false);
        if (decision === "block") {
            const categories = combinedDetections.map((d) => d.category);
            const previews = combinedDetections.map((d) => config.logging.redactValues ? (0, validation_1.redactPreview)(d.matchedText, config.logging.previewChars) : undefined);
            emitBlock(summarizeDetections(config.mode, categories, previews));
        }
        else if (decision === "warn") {
            const categories = combinedDetections.map((d) => d.category);
            const previews = combinedDetections.map((d) => config.logging.redactValues ? (0, validation_1.redactPreview)(d.matchedText, config.logging.previewChars) : undefined);
            emitWarn(summarizeDetections(config.mode, categories, previews));
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
