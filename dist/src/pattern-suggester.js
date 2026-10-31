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
exports.normalizeShape = normalizeShape;
exports.buildCandidateRegex = buildCandidateRegex;
exports.suggestPatterns = suggestPatterns;
const crypto = __importStar(require("crypto"));
const redos_check_1 = require("./redos-check");
const SPECIAL_CHARS = new Set([".", "*", "+", "?", "^", "$", "{", "}", "(", ")", "|", "[", "]", "\\", "/"]);
/**
 * Collapses a string to a rough structural skeleton: every run of letters becomes
 * "A", every run of digits becomes "9", everything else (punctuation, whitespace,
 * symbols) is kept literally. Two strings with the same skeleton are treated as
 * "similar" (T4.2, REQ-SI-02) — a standard, lightweight log-template-mining
 * heuristic, not a formal generalizer.
 */
function normalizeShape(s) {
    return s.replace(/[A-Za-z]+/g, "A").replace(/[0-9]+/g, "9");
}
/**
 * Turns a shape skeleton directly into a regex source: "A" -> `[A-Za-z]+`, "9" ->
 * `\d+`, anything else -> its escaped literal form. Safe to walk character-by-
 * character with no escaping collisions: every real letter or digit — including a
 * literal "A" or "9" that appeared in the original text — was already absorbed into
 * an "A"/"9" run by normalizeShape(), so the only "A"/"9" characters reaching this
 * function are placeholders.
 */
function buildCandidateRegex(shape) {
    let out = "";
    for (const ch of shape) {
        if (ch === "A")
            out += "[A-Za-z]+";
        else if (ch === "9")
            out += "\\d+";
        else if (SPECIAL_CHARS.has(ch))
            out += `\\${ch}`;
        else
            out += ch;
    }
    return out;
}
/**
 * Groups feedback records into candidate regex suggestions for human review
 * (T4.2/REQ-SI-02). Every candidate is pre-validated with `checkRedosSafety()` before
 * a human ever sees it (defense in depth — `review-patterns.ts` re-validates again at
 * approval time, REQ-SI-04, since a human-edited regex is untrusted input too).
 * Groups below `minHits` are too thin to generalize from safely and are dropped;
 * groups whose shape signature is already in `approvedSignatures` (a pattern already
 * exists for that shape) are excluded so the same suggestion never recurs.
 */
function suggestPatterns(records, options) {
    const groups = new Map();
    for (const record of records) {
        if (!record.evidencePreview)
            continue;
        const key = `${record.category}::${normalizeShape(record.evidencePreview)}`;
        const list = groups.get(key);
        if (list)
            list.push(record);
        else
            groups.set(key, [record]);
    }
    const suggestions = [];
    for (const [key, group] of groups) {
        if (group.length < options.minHits)
            continue;
        if (options.approvedSignatures.has(key))
            continue;
        const first = group[0];
        const regex = buildCandidateRegex(normalizeShape(first.evidencePreview));
        if (!(0, redos_check_1.checkRedosSafety)(regex).safe)
            continue;
        const id = `${first.category}-${crypto.createHash("sha1").update(key).digest("hex").slice(0, 8)}`;
        suggestions.push({
            id,
            category: first.category,
            regex,
            shapeSignature: key,
            hitCount: group.length,
            examples: group.slice(0, 3).map((r) => r.evidencePreview),
        });
    }
    return suggestions.sort((a, b) => b.hitCount - a.hitCount);
}
