"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decide = decide;
/**
 * Pure decision function, deliberately separated from scan-prompt.ts's stdin/stdout
 * I/O so it's unit-testable without spawning a process (T1.2, T1.5, T1.7).
 *
 * - `unresolvedRisk` takes priority: fail closed (block) in block mode, fail open +
 *   warn in warn/audit mode (REQ-ENF-05, D6, TM-8) — including audit mode, where this
 *   still surfaces a warning even though normal audit-mode detections don't. Two
 *   distinct callers set this flag: scan-prompt.ts's top-level catch block for an
 *   unexpected pipeline crash (T1.7), and a Tier 2 request that timed out or failed
 *   outright (REQ-T2-06) — both mean "we couldn't fully evaluate this prompt," which
 *   gets the same fail-open/closed treatment either way.
 * - Otherwise: no detections -> allow. block mode -> block. warn mode -> warn.
 *   audit mode -> allow (it only records, per REQ-ENF-03 "without interrupting the user").
 */
function decide(mode, detections, unresolvedRisk) {
    if (unresolvedRisk) {
        return mode === "block" ? "block" : "warn";
    }
    if (detections.length === 0)
        return "allow";
    if (mode === "block")
        return "block";
    if (mode === "warn")
        return "warn";
    return "allow";
}
