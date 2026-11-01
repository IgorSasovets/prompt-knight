// Central input-validation / safe-output helpers (T1.11, REQ-SEC-01, REQ-SEC-09).
// Every piece of user-facing output flows through here so a raw secret value or an
// internal stack trace can never leak into a block reason, systemMessage, or log line.

import { Detection } from "./types";

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Returns at most `previewChars` characters of `value`, masked with a trailing
 * "***" if truncated. `previewChars <= 0` disables the preview entirely (REQ-LOG-04).
 */
export function redactPreview(value: string, previewChars: number): string | undefined {
  if (previewChars <= 0) return undefined;
  const n = Math.min(previewChars, value.length);
  const slice = value.slice(0, n);
  return value.length > n ? `${slice}***` : slice;
}

// Never includes err.message verbatim: a thrown error could echo back attacker-
// controlled prompt content or a filesystem path, which must not reach the user.
export function sanitizeErrorForUser(_err: unknown): string {
  return "PromptKnight encountered an internal error while scanning this prompt.";
}

export function expandHome(p: string, homedir: string): string {
  if (p === "~") return homedir;
  if (p.startsWith("~/") || p.startsWith("~\\")) return homedir + p.slice(1);
  return p;
}

export interface OffsetRedactionResult {
  text: string;
  fullyVerifiable: boolean;
}

/**
 * Splices `text` at each detection's verified offset, replacing the matched span with
 * a category-labeled placeholder (REQ-TOOL-07, D23). A detection counts as verified
 * only if `text.slice(index, index + length) === matchedText` — Tier 2's detections
 * always carry a synthetic `index:0, length:0` placeholder (see tier2-ollama.ts's
 * buildDetections()) that can never pass this check, by design (Tier 2 never reports
 * a real excerpt). If any detection in the batch fails verification, the whole batch
 * is reported `fullyVerifiable:false` and the original `text` is returned unchanged —
 * the caller must fall back to a full-field placeholder rather than trust a partial
 * splice, so a Tier 2-only detection is never silently left unredacted.
 */
export function redactByOffsets(
  text: string,
  detections: Detection[],
  placeholderFor: (category: string) => string
): OffsetRedactionResult {
  if (detections.length === 0) return { text, fullyVerifiable: false };

  const verifiedCount = detections.filter((d) => text.slice(d.index, d.index + d.length) === d.matchedText).length;
  if (verifiedCount !== detections.length) return { text, fullyVerifiable: false };

  // Splice from the end so earlier offsets stay valid as later ones are replaced.
  const sorted = [...detections].sort((a, b) => b.index - a.index);
  let result = text;
  for (const d of sorted) {
    result = result.slice(0, d.index) + placeholderFor(d.category) + result.slice(d.index + d.length);
  }
  return { text: result, fullyVerifiable: true };
}
