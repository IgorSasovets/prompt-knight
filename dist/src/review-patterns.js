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
exports.readFeedbackRecords = readFeedbackRecords;
exports.purgeFeedbackRecords = purgeFeedbackRecords;
exports.readApprovedSignatures = readApprovedSignatures;
exports.writeApprovedSignatures = writeApprovedSignatures;
exports.appendCustomPattern = appendCustomPattern;
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const readline = __importStar(require("readline"));
const config_loader_1 = require("./config-loader");
const redos_check_1 = require("./redos-check");
const pattern_suggester_1 = require("./pattern-suggester");
function readFeedbackRecords(feedbackLogPath) {
    if (!fs.existsSync(feedbackLogPath))
        return [];
    const raw = fs.readFileSync(feedbackLogPath, "utf8");
    const records = [];
    for (const line of raw.split("\n")) {
        if (!line.trim())
            continue;
        try {
            const parsed = JSON.parse(line);
            if (typeof parsed.category === "string" &&
                typeof parsed.evidencePreview === "string" &&
                typeof parsed.confidence === "number") {
                records.push(parsed);
            }
        }
        catch {
            // skip a malformed line rather than fail the whole read
        }
    }
    return records;
}
/** Rewrites feedback.jsonl, dropping only records whose signature was just approved —
 * their evidence has graduated into a real pattern, so shorter retention is the more
 * secure choice. Skipped suggestions' records are left untouched. */
function purgeFeedbackRecords(feedbackLogPath, signaturesToPurge) {
    if (signaturesToPurge.size === 0 || !fs.existsSync(feedbackLogPath))
        return;
    const raw = fs.readFileSync(feedbackLogPath, "utf8");
    const kept = raw.split("\n").filter((line) => {
        if (!line.trim())
            return false;
        try {
            const parsed = JSON.parse(line);
            const signature = `${parsed.category}::${(0, pattern_suggester_1.normalizeShape)(parsed.evidencePreview ?? "")}`;
            return !signaturesToPurge.has(signature);
        }
        catch {
            return false;
        }
    });
    fs.writeFileSync(feedbackLogPath, kept.length > 0 ? `${kept.join("\n")}\n` : "", { mode: 0o600 });
}
function readApprovedSignatures(statePath) {
    try {
        const raw = fs.readFileSync(statePath, "utf8");
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed.approvedSignatures))
            return new Set(parsed.approvedSignatures);
    }
    catch {
        // no state file yet, or it's malformed — start fresh rather than fail the CLI
    }
    return new Set();
}
function writeApprovedSignatures(statePath, signatures) {
    fs.mkdirSync(path.dirname(statePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(statePath, JSON.stringify({ approvedSignatures: [...signatures] }, null, 2), { mode: 0o600 });
}
/**
 * Validates (compile + ReDoS-safety check, REQ-SI-04) and appends an approved pattern
 * to the custom pattern file. `customPatternsPath` must already be the sandboxed,
 * resolved path (the caller resolves it via `resolveSandboxedPath`, the same helper
 * `tier1-engine.ts`'s loader uses) — this function only does validation + the file
 * read/write.
 */
function appendCustomPattern(customPatternsPath, pattern) {
    const check = (0, redos_check_1.checkRedosSafety)(pattern.regex, pattern.flags ?? "");
    if (!check.safe)
        return { ok: false, reason: check.reason };
    try {
        new RegExp(pattern.regex, pattern.flags ?? "");
    }
    catch (err) {
        return { ok: false, reason: `pattern does not compile: ${err.message}` };
    }
    let existing = [];
    try {
        if (fs.existsSync(customPatternsPath)) {
            const parsed = JSON.parse(fs.readFileSync(customPatternsPath, "utf8"));
            if (Array.isArray(parsed))
                existing = parsed;
        }
    }
    catch {
        existing = [];
    }
    existing.push(pattern);
    fs.writeFileSync(customPatternsPath, JSON.stringify(existing, null, 2));
    return { ok: true };
}
function formatSuggestion(s) {
    const example = s.examples[0] ?? "";
    return `${s.category} (${s.hitCount} hits)   ${s.regex}\n    e.g. "${example}"`;
}
async function runInteractiveReview() {
    const homedir = os.homedir();
    const pluginRoot = path.resolve(__dirname, "..", "..");
    const projectRoot = process.cwd();
    const { config, userConfigDir } = (0, config_loader_1.loadConfig)(pluginRoot, projectRoot, homedir);
    const logDir = path.join(userConfigDir, "logs");
    const feedbackLogPath = path.join(logDir, "feedback.jsonl");
    const statePath = path.join(logDir, "pattern-suggestions-state.json");
    const records = readFeedbackRecords(feedbackLogPath);
    const approvedSignatures = readApprovedSignatures(statePath);
    const suggestions = (0, pattern_suggester_1.suggestPatterns)(records, {
        minHits: config.feedback.minHitsForSuggestion,
        approvedSignatures,
    });
    if (suggestions.length === 0) {
        console.log("No new pattern suggestions.");
        return;
    }
    const sandboxErrors = [];
    const customPatternsPath = (0, config_loader_1.resolveSandboxedPath)(config.tier1.customPatternsFile, pluginRoot, [pluginRoot, userConfigDir, projectRoot], "tier1.customPatternsFile", sandboxErrors);
    if (!customPatternsPath) {
        console.error(`Cannot write approved patterns: ${sandboxErrors.join(" ")}`);
        return;
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = (q) => new Promise((resolve) => rl.question(q, resolve));
    console.log(`Found ${suggestions.length} new pattern suggestion(s):`);
    const purgedSignatures = new Set();
    let approvedCount = 0;
    let skippedCount = 0;
    for (const suggestion of suggestions) {
        let current = suggestion;
        let decided = false;
        while (!decided) {
            console.log(`\n${formatSuggestion(current)}`);
            const answer = (await ask("[a]pprove [s]kip [e]dit > ")).trim().toLowerCase();
            if (answer === "a") {
                const result = appendCustomPattern(customPatternsPath, {
                    id: current.id,
                    category: current.category,
                    regex: current.regex,
                });
                if (result.ok) {
                    approvedSignatures.add(current.shapeSignature);
                    purgedSignatures.add(current.shapeSignature);
                    approvedCount += 1;
                    console.log(`Approved "${current.id}".`);
                }
                else {
                    console.log(`Could not approve: ${result.reason}`);
                }
                decided = true;
            }
            else if (answer === "s") {
                skippedCount += 1;
                decided = true;
            }
            else if (answer === "e") {
                const newRegex = (await ask("New regex> ")).trim();
                const check = (0, redos_check_1.checkRedosSafety)(newRegex);
                if (!check.safe) {
                    console.log(`Rejected: ${check.reason}`);
                    continue;
                }
                current = { ...current, regex: newRegex };
            }
            else {
                console.log('Please answer "a", "s", or "e".');
            }
        }
    }
    rl.close();
    writeApprovedSignatures(statePath, approvedSignatures);
    purgeFeedbackRecords(feedbackLogPath, purgedSignatures);
    console.log(`\nApproved ${approvedCount}, skipped ${skippedCount}.`);
}
if (require.main === module) {
    void runInteractiveReview();
}
