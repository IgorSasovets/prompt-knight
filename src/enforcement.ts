import { Detection, Mode } from "./types";

export type Decision = "allow" | "warn" | "block";

/**
 * Pure decision function, deliberately separated from scan-prompt.ts's stdin/stdout
 * I/O so it's unit-testable without spawning a process (T1.2, T1.5, T1.7).
 *
 * - `internalError` takes priority: fail closed (block) in block mode, fail open + warn
 *   in warn/audit mode (REQ-ENF-05, D6, TM-8) — including audit mode, where an internal
 *   error still surfaces a warning even though normal audit-mode detections don't.
 * - Otherwise: no detections -> allow. block mode -> block. warn mode -> warn.
 *   audit mode -> allow (it only records, per REQ-ENF-03 "without interrupting the user").
 */
export function decide(mode: Mode, detections: Detection[], internalError: boolean): Decision {
  if (internalError) {
    return mode === "block" ? "block" : "warn";
  }
  if (detections.length === 0) return "allow";
  if (mode === "block") return "block";
  if (mode === "warn") return "warn";
  return "allow";
}
