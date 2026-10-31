// Central input-validation / safe-output helpers (T1.11, REQ-SEC-01, REQ-SEC-09).
// Every piece of user-facing output flows through here so a raw secret value or an
// internal stack trace can never leak into a block reason, systemMessage, or log line.

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
