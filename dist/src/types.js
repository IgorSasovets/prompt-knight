"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SECURE_DEFAULTS = void 0;
// Hardcoded fallback, independent of config/default.json on disk — the last line of
// defense if the shipped default config is itself missing or unreadable (REQ-CFG-03).
exports.SECURE_DEFAULTS = {
    mode: "block",
    maxPromptBytes: 1048576,
    tier1: {
        enabled: true,
        patterns: {
            aws_keys: true,
            aws_secrets: true,
            aws_accounts: true,
            aws_arns: true,
            db_strings: true,
            jwt_tokens: true,
            npm_tokens: true,
            private_ips: true,
        },
        customPatternsFile: "patterns/custom.json",
        patternTimeoutMs: 50,
        allowlist: [],
    },
    gitleaks: {
        enabled: false,
        binaryPath: "gitleaks",
        pinnedVersion: "8.x.y",
        expectedSha256: "",
        configPath: null,
        timeoutMs: 5000,
    },
    tier2: {
        enabled: false,
        ollamaUrl: "http://localhost:11434",
        allowNonLocal: false,
        model: "llama3.2:3b",
        timeoutMs: 15000,
        confidenceThreshold: 0.7,
        fallbackOnError: "mode-dependent",
    },
    logging: {
        enabled: true,
        logDir: "~/.prompt-knight/logs",
        logFile: "detections.jsonl",
        redactValues: true,
        previewChars: 4,
    },
    feedback: {
        enabled: false,
        suggestPatterns: true,
        autoExtendPatterns: false,
        minHitsForSuggestion: 3,
        // Deliberately more generous than logging.previewChars (default 4): that value is
        // tuned for human-readable audit-log debugging context, not for deriving a
        // multi-character structural regex. Still bounded/truncated, never the raw value,
        // and already capped upstream at 200 chars by tier2-ollama.ts's evidence field.
        evidencePreviewChars: 64,
    },
    toolOutput: {
        // On by default (REQ-SEC-08): this closes a real reported leak (Read/Grep/Bash
        // content reaching the model unscanned) at Tier 1's near-zero per-call cost,
        // same precedent as tier1.enabled above. gitleaks/tier2 stay independently
        // opt-in exactly as they already are for the prompt channel (D24).
        enabled: true,
        tools: ["Read", "Grep", "Bash"],
        denyPathPatterns: [
            ".env",
            ".env.*",
            "*.pem",
            "*.key",
            "id_rsa*",
            "id_ed25519*",
            "*.p12",
            "*.pfx",
            ".aws/credentials",
            ".ssh/*",
        ],
    },
};
