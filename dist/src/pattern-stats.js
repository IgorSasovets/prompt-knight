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
exports.recordPatternActivity = recordPatternActivity;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
function statsFilePath(userConfigDir) {
    return path.join(userConfigDir, "logs", "pattern-stats.json");
}
function readStats(filePath) {
    try {
        const raw = fs.readFileSync(filePath, "utf8");
        const parsed = JSON.parse(raw);
        if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
            return parsed;
        }
        return {};
    }
    catch {
        return {};
    }
}
function writeStats(filePath, stats) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    fs.chmodSync(path.dirname(filePath), 0o700);
    fs.writeFileSync(filePath, JSON.stringify(stats, null, 2), { mode: 0o600 });
    fs.chmodSync(filePath, 0o600);
}
/**
 * Persists per-pattern match/suppression counts across hook invocations (REQ-SI-05),
 * keyed by `Detection.patternId` — uniform across all four detection sources (tier1's
 * category, a custom pattern id, `gitleaks:<RuleID>`, `tier2:<category>`).
 *
 * Each hook invocation is a fresh process, so this does a read-merge-write against a
 * small JSON file; under concurrent invocations this accepts last-write-wins rather
 * than file locking — an acceptable tradeoff for a local, single-user, low-concurrency
 * tool. Never throws: a failure here must never affect enforcement, so it's caught and
 * returned as an optional warning instead.
 */
function recordPatternActivity(matched, suppressed, userConfigDir) {
    if (matched.length === 0 && suppressed.length === 0)
        return {};
    const filePath = statsFilePath(userConfigDir);
    try {
        const stats = readStats(filePath);
        const now = new Date().toISOString();
        for (const d of matched) {
            const entry = stats[d.patternId] ?? { matchCount: 0, suppressedCount: 0 };
            entry.matchCount += 1;
            entry.lastMatchedAt = now;
            stats[d.patternId] = entry;
        }
        for (const d of suppressed) {
            const entry = stats[d.patternId] ?? { matchCount: 0, suppressedCount: 0 };
            entry.suppressedCount += 1;
            stats[d.patternId] = entry;
        }
        writeStats(filePath, stats);
        return {};
    }
    catch (err) {
        return { warning: `PromptKnight: failed to update pattern-stats.json: ${err.message}` };
    }
}
