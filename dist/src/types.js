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
    },
};
