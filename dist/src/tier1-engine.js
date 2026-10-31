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
exports.loadPatterns = loadPatterns;
exports.isAllowlisted = isAllowlisted;
exports.dedupeDetections = dedupeDetections;
exports.shutdownPatternWorker = shutdownPatternWorker;
exports.truncateToByteLimit = truncateToByteLimit;
exports.scan = scan;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const worker_threads_1 = require("worker_threads");
const redos_check_1 = require("./redos-check");
const config_loader_1 = require("./config-loader");
function readPatternDefinitions(filePath) {
    try {
        const raw = fs.readFileSync(filePath, "utf8");
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) {
            return { definitions: [], error: `${filePath} must contain a JSON array of pattern definitions` };
        }
        return { definitions: parsed };
    }
    catch (err) {
        return { definitions: [], error: `Failed to read/parse ${filePath}: ${err.message}` };
    }
}
function compileOne(def, trusted, loadErrors) {
    const flags = def.flags ?? "";
    const check = (0, redos_check_1.checkRedosSafety)(def.regex, flags);
    if (!check.safe) {
        loadErrors.push(`Skipping pattern "${def.id}": ${check.reason}`);
        return null;
    }
    try {
        const regex = new RegExp(def.regex, flags.includes("g") ? flags : `${flags}g`);
        return { id: def.id, category: def.category, regex, source: def.regex, flags, trusted };
    }
    catch (err) {
        loadErrors.push(`Skipping pattern "${def.id}": failed to compile: ${err.message}`);
        return null;
    }
}
/**
 * Loads the built-in pattern library plus, where configured and sandbox-safe, the
 * custom pattern file (REQ-T1-01/03, T1.4/T1.9). Built-ins are only filtered by the
 * per-category toggles in `tier1.patterns`; everything goes through the ReDoS check.
 */
function loadPatterns(pluginRoot, tier1Config, allowedRoots) {
    const loadErrors = [];
    const patterns = [];
    const builtinPath = path.join(pluginRoot, "patterns", "builtin.json");
    const builtin = readPatternDefinitions(builtinPath);
    if (builtin.error)
        loadErrors.push(builtin.error);
    for (const def of builtin.definitions) {
        const toggleKey = def.category;
        if (tier1Config.patterns[toggleKey] === false)
            continue;
        const compiled = compileOne(def, true, loadErrors);
        if (compiled)
            patterns.push(compiled);
    }
    const resolvedCustomPath = (0, config_loader_1.resolveSandboxedPath)(tier1Config.customPatternsFile, pluginRoot, allowedRoots, "tier1.customPatternsFile", loadErrors);
    if (resolvedCustomPath && fs.existsSync(resolvedCustomPath)) {
        const custom = readPatternDefinitions(resolvedCustomPath);
        if (custom.error)
            loadErrors.push(custom.error);
        for (const def of custom.definitions) {
            const compiled = compileOne(def, false, loadErrors);
            if (compiled)
                patterns.push(compiled);
        }
    }
    return { patterns, loadErrors };
}
function isAllowlisted(matchedText, allowlist) {
    return allowlist.some((entry) => matchedText.includes(entry));
}
/**
 * Collapses detections that report the identical matched secret value, regardless of
 * which detector found it (REQ-GL-05). Earlier entries win, so callers that want
 * tier1's more specific category name to take priority over gitleaks' should
 * concatenate tier1 detections first.
 */
function dedupeDetections(detections) {
    const seenByValue = new Set();
    const seenByLocation = new Set();
    return detections.filter((d) => {
        if (seenByValue.has(d.matchedText))
            return false;
        const locationKey = `${d.category}:${d.index}:${d.length}`;
        if (seenByLocation.has(locationKey))
            return false;
        seenByValue.add(d.matchedText);
        seenByLocation.add(locationKey);
        return true;
    });
}
function runTrusted(pattern, text) {
    const detections = [];
    const regex = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
    let match;
    while ((match = regex.exec(text)) !== null) {
        detections.push({
            category: pattern.category,
            source: "tier1",
            patternId: pattern.id,
            index: match.index,
            length: match[0].length,
            matchedText: match[0],
        });
        if (match[0].length === 0)
            regex.lastIndex += 1;
    }
    return detections;
}
let workerHandle = null;
let nextRequestId = 1;
function getWorker(workerScriptPath) {
    if (!workerHandle) {
        workerHandle = new worker_threads_1.Worker(workerScriptPath);
    }
    return workerHandle;
}
function respawnWorker(workerScriptPath) {
    if (workerHandle) {
        void workerHandle.terminate();
    }
    workerHandle = new worker_threads_1.Worker(workerScriptPath);
    return workerHandle;
}
/**
 * Runs a single untrusted (custom) pattern against `text` in a worker thread, bounded
 * by `timeoutMs`. On timeout the worker is terminated — a real guarantee, not a best
 * effort — and the pattern is treated as non-matching (REQ-T1-05).
 */
async function runUntrusted(pattern, text, timeoutMs, workerScriptPath, timeouts) {
    const worker = getWorker(workerScriptPath);
    const id = nextRequestId++;
    const request = { id, source: pattern.source, flags: pattern.flags, text };
    return new Promise((resolve) => {
        let settled = false;
        const timer = setTimeout(() => {
            if (settled)
                return;
            settled = true;
            timeouts.push(`Pattern "${pattern.id}" exceeded ${timeoutMs}ms and was aborted`);
            respawnWorker(workerScriptPath);
            resolve([]);
        }, timeoutMs);
        const onMessage = (response) => {
            if (response.id !== id || settled)
                return;
            settled = true;
            clearTimeout(timer);
            worker.off("message", onMessage);
            if (response.error || !response.matches) {
                resolve([]);
                return;
            }
            resolve(response.matches.map((m) => ({
                category: pattern.category,
                source: "custom",
                patternId: pattern.id,
                index: m.index,
                length: m.length,
                matchedText: m.matchedText,
            })));
        };
        worker.on("message", onMessage);
        worker.postMessage(request);
    });
}
function shutdownPatternWorker() {
    if (workerHandle) {
        void workerHandle.terminate();
        workerHandle = null;
    }
}
function truncateToByteLimit(text, maxBytes) {
    if (Buffer.byteLength(text, "utf8") <= maxBytes)
        return text;
    // Binary-search the largest prefix (in UTF-16 code units) whose UTF-8 byte length
    // stays within the bound, avoiding a split multi-byte character at the boundary.
    let low = 0;
    let high = text.length;
    while (low < high) {
        const mid = Math.ceil((low + high) / 2);
        if (Buffer.byteLength(text.slice(0, mid), "utf8") <= maxBytes) {
            low = mid;
        }
        else {
            high = mid - 1;
        }
    }
    return text.slice(0, low);
}
async function scan(text, patterns, options) {
    const bounded = truncateToByteLimit(text, options.maxPromptBytes);
    const timeouts = [];
    let detections = [];
    for (const pattern of patterns) {
        if (pattern.trusted) {
            const start = Date.now();
            const found = runTrusted(pattern, bounded);
            if (Date.now() - start > options.patternTimeoutMs) {
                timeouts.push(`Pattern "${pattern.id}" exceeded ${options.patternTimeoutMs}ms (built-in, measured post-hoc)`);
            }
            detections = detections.concat(found);
        }
        else {
            const found = await runUntrusted(pattern, bounded, options.patternTimeoutMs, options.workerScriptPath, timeouts);
            detections = detections.concat(found);
        }
    }
    const filtered = detections.filter((d) => !isAllowlisted(d.matchedText, options.allowlist));
    const suppressed = detections.filter((d) => isAllowlisted(d.matchedText, options.allowlist));
    const deduped = dedupeDetections(filtered);
    return { detections: deduped, suppressed, timeouts };
}
