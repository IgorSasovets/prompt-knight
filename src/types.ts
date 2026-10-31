export type Mode = "block" | "warn" | "audit";

export interface PatternDefinition {
  id: string;
  category: string;
  description?: string;
  regex: string;
  flags?: string;
}

export interface Detection {
  category: string;
  source: "tier1" | "custom";
  patternId: string;
  index: number;
  length: number;
  matchedText: string;
}

export interface Tier1PatternToggles {
  aws_keys: boolean;
  aws_secrets: boolean;
  aws_accounts: boolean;
  aws_arns: boolean;
  db_strings: boolean;
  jwt_tokens: boolean;
  npm_tokens: boolean;
  private_ips: boolean;
}

export interface Tier1Config {
  enabled: boolean;
  patterns: Tier1PatternToggles;
  customPatternsFile: string;
  patternTimeoutMs: number;
  allowlist: string[];
}

export interface GitleaksConfig {
  enabled: boolean;
  binaryPath: string;
  pinnedVersion: string;
  expectedSha256: string;
  configPath: string | null;
}

export interface Tier2Config {
  enabled: boolean;
  ollamaUrl: string;
  allowNonLocal: boolean;
  model: string;
  timeoutMs: number;
  confidenceThreshold: number;
  fallbackOnError: string;
}

export interface LoggingConfig {
  enabled: boolean;
  logDir: string;
  logFile: string;
  redactValues: boolean;
  previewChars: number;
}

export interface FeedbackConfig {
  enabled: boolean;
  suggestPatterns: boolean;
  autoExtendPatterns: boolean;
}

export interface Config {
  mode: Mode;
  maxPromptBytes: number;
  tier1: Tier1Config;
  gitleaks: GitleaksConfig;
  tier2: Tier2Config;
  logging: LoggingConfig;
  feedback: FeedbackConfig;
}

// Hardcoded fallback, independent of config/default.json on disk — the last line of
// defense if the shipped default config is itself missing or unreadable (REQ-CFG-03).
export const SECURE_DEFAULTS: Config = {
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

export interface ScanOutcome {
  decision: "allow" | "warn" | "block";
  detections: Detection[];
  configErrors: string[];
  patternLoadErrors: string[];
  patternTimeouts: string[];
  internalError: boolean;
}
