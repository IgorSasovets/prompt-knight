"use strict";
// Central input-validation / safe-output helpers (T1.11, REQ-SEC-01, REQ-SEC-09).
// Every piece of user-facing output flows through here so a raw secret value or an
// internal stack trace can never leak into a block reason, systemMessage, or log line.
Object.defineProperty(exports, "__esModule", { value: true });
exports.isPlainObject = isPlainObject;
exports.redactPreview = redactPreview;
exports.sanitizeErrorForUser = sanitizeErrorForUser;
exports.expandHome = expandHome;
function isPlainObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
/**
 * Returns at most `previewChars` characters of `value`, masked with a trailing
 * "***" if truncated. `previewChars <= 0` disables the preview entirely (REQ-LOG-04).
 */
function redactPreview(value, previewChars) {
    if (previewChars <= 0)
        return undefined;
    const n = Math.min(previewChars, value.length);
    const slice = value.slice(0, n);
    return value.length > n ? `${slice}***` : slice;
}
// Never includes err.message verbatim: a thrown error could echo back attacker-
// controlled prompt content or a filesystem path, which must not reach the user.
function sanitizeErrorForUser(_err) {
    return "PromptKnight encountered an internal error while scanning this prompt.";
}
function expandHome(p, homedir) {
    if (p === "~")
        return homedir;
    if (p.startsWith("~/") || p.startsWith("~\\"))
        return homedir + p.slice(1);
    return p;
}
