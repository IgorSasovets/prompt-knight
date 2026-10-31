import * as fs from "fs";
import * as path from "path";
import { Config, Detection } from "./types";
import { expandHome, redactPreview } from "./validation";
import { resolveSandboxedPath } from "./config-loader";

export interface LogWriteResult {
  warning?: string;
}

function resolveLogPath(
  loggingConfig: Config["logging"],
  homedir: string,
  userConfigDir: string,
  sandboxErrors: string[]
): string {
  const expandedDir = expandHome(loggingConfig.logDir, homedir);
  const resolvedDir = resolveSandboxedPath(expandedDir, homedir, [userConfigDir], "logging.logDir", sandboxErrors);
  const logDir = resolvedDir ?? path.join(userConfigDir, "logs");
  if (!resolvedDir) {
    sandboxErrors.push(
      `logging.logDir "${loggingConfig.logDir}" resolves outside ~/.prompt-knight/; using the default log directory instead.`
    );
  }
  return path.join(logDir, loggingConfig.logFile);
}

/**
 * Appends pre-built JSON lines to the audit log. Creates the log directory with 0700
 * and the log file with 0600, re-chmod'ing both on every write so the invariant holds
 * even if either pre-existed with looser permissions (REQ-LOG-03, D12). Never throws
 * into the enforcement path: any failure becomes a warning (REQ-LOG-05).
 */
function appendLines(logPath: string, lines: string[]): LogWriteResult {
  if (lines.length === 0) return {};
  try {
    fs.mkdirSync(path.dirname(logPath), { recursive: true, mode: 0o700 });
    fs.chmodSync(path.dirname(logPath), 0o700);

    const fd = fs.openSync(logPath, "a", 0o600);
    try {
      fs.chmodSync(logPath, 0o600);
      fs.writeSync(fd, `${lines.join("\n")}\n`);
    } finally {
      fs.closeSync(fd);
    }
  } catch (err) {
    return { warning: `PromptKnight: audit log unwritable, continuing without logging (${(err as Error).message})` };
  }
  return {};
}

/** Appends one JSON line per detection to the audit log (REQ-LOG-01/02). */
export function logDetections(
  loggingConfig: Config["logging"],
  mode: string,
  detections: Detection[],
  homedir: string,
  userConfigDir: string
): LogWriteResult {
  if (!loggingConfig.enabled || detections.length === 0) return {};

  const sandboxErrors: string[] = [];
  const logPath = resolveLogPath(loggingConfig, homedir, userConfigDir, sandboxErrors);

  const timestamp = new Date().toISOString();
  const lines = detections.map((d) => {
    const entry: Record<string, unknown> = {
      timestamp,
      mode,
      category: d.category,
      location: { index: d.index, length: d.length },
    };
    if (loggingConfig.redactValues) {
      const preview = redactPreview(d.matchedText, loggingConfig.previewChars);
      if (preview !== undefined) entry.preview = preview;
    } else {
      // User has explicitly opted out of redaction — their own risk, not the default.
      entry.value = d.matchedText;
    }
    return JSON.stringify(entry);
  });

  const writeResult = appendLines(logPath, lines);
  const warnings = [...sandboxErrors, ...(writeResult.warning ? [writeResult.warning] : [])];
  return warnings.length > 0 ? { warning: warnings.join(" ") } : {};
}

/**
 * Appends operational diagnostic events (config errors, pattern-load errors,
 * pattern-timeout events — REQ-CFG-04, REQ-T1-05, REQ-T1-07) to the same audit log,
 * distinguished from detection entries by an "event" field instead of "category".
 */
export function logOperationalEvents(
  loggingConfig: Config["logging"],
  event: string,
  messages: string[],
  homedir: string,
  userConfigDir: string
): LogWriteResult {
  if (!loggingConfig.enabled || messages.length === 0) return {};

  const sandboxErrors: string[] = [];
  const logPath = resolveLogPath(loggingConfig, homedir, userConfigDir, sandboxErrors);

  const timestamp = new Date().toISOString();
  const lines = messages.map((message) => JSON.stringify({ timestamp, event, message }));

  const writeResult = appendLines(logPath, lines);
  const warnings = [...sandboxErrors, ...(writeResult.warning ? [writeResult.warning] : [])];
  return warnings.length > 0 ? { warning: warnings.join(" ") } : {};
}
