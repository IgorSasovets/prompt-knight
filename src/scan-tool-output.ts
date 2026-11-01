#!/usr/bin/env node
// PostToolUse hook (T6.4/T6.5, REQ-TOOL-04..10, D19/D22/D23): closes OD2 by running
// Read/Grep/Bash content through the same Tier1/gitleaks/Tier2 pipeline that
// scan-prompt.ts already runs on prompt text, then redacting in place via
// `updatedToolOutput` before the content reaches the model.
//
// Critical constraint (verified empirically against a real Claude Code session,
// not assumed from docs — see .specs/promptknight/design.md D22): a top-level
// `decision:"block"` alone does NOT stop the original tool output from reaching the
// model; only `hookSpecificOutput.updatedToolOutput`, re-emitted in the tool's exact
// original shape, does. A shape mismatch is a silent DLP bypass, not a crash — so
// `tool-output-extract.ts`'s rebuild only ever overwrites the field it read.
//
// Each extracted field (Read's file content; Grep's matched content; Bash's stdout
// and stderr independently) is scanned and decided on its own — a clean stdout next
// to a leaking stderr should redact only the stderr, not blank the whole call — and
// the tool-level outcome is the highest-precedence field outcome (block > warn >
// allow), the same "escalate, never downgrade" spirit D9 already applies to Tier 2
// vs. Tier 1.
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { loadConfig } from "./config-loader";
import { decide } from "./enforcement";
import { logDetections, logFeedback, logOperationalEvents } from "./feedback-logger";
import { scanWithGitleaks } from "./gitleaks-adapter";
import { recordPatternActivity } from "./pattern-stats";
import { CompiledPattern, dedupeDetections, isAllowlisted, loadPatterns, scan, shutdownPatternWorker } from "./tier1-engine";
import { extractScannableFields, rebuildToolResponse, ScanField } from "./tool-output-extract";
import { callOllama, isLocalHostname, Tier2Evidence } from "./tier2-ollama";
import { Config, Detection } from "./types";
import { redactByOffsets, redactPreview } from "./validation";

interface HookPayload {
  tool_name?: unknown;
  tool_response?: unknown;
  cwd?: unknown;
}

interface FieldRecord {
  field: ScanField;
  text: string;
  detections: Detection[];
  decision: "allow" | "warn" | "block";
  allMatched: Detection[];
  allSuppressed: Detection[];
  tier2Evidence: Tier2Evidence[];
}

function readStdin(): string {
  try {
    return fs.readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function emitAllow(): void {
  process.exitCode = 0;
}

function placeholderFor(category: string): string {
  return `[REDACTED:${category}]`;
}

const FULL_FIELD_PLACEHOLDER =
  "[PromptKnight: content withheld — a possible secret was detected but could not be safely isolated for redaction]";

function buildReason(toolName: string, label: string, records: FieldRecord[], config: Config): string {
  const withDetections = records.filter((r) => r.detections.length > 0);
  const unresolvedOnly = records.filter((r) => r.detections.length === 0);
  const parts: string[] = [];

  if (withDetections.length > 0) {
    const categories = Array.from(new Set(withDetections.flatMap((r) => r.detections.map((d) => d.category))));
    const previews = withDetections
      .flatMap((r) => r.detections)
      .map((d) => (config.logging.redactValues ? redactPreview(d.matchedText, config.logging.previewChars) : undefined))
      .filter((p): p is string => p !== undefined);
    const previewText = previews.length > 0 ? ` (preview: ${previews.join(", ")})` : "";
    parts.push(`possible ${categories.join(", ")} detected${previewText}`);
  }
  if (unresolvedOnly.length > 0) {
    parts.push(
      `semantic analysis (Tier 2) could not complete for ${unresolvedOnly.map((r) => r.field).join(", ")}, and the configured mode fails closed when a check can't run`
    );
  }
  return `PromptKnight ${label} this ${toolName} output: ${parts.join("; ")}.`;
}

async function evaluateField(
  text: string,
  field: ScanField,
  config: Config,
  patterns: CompiledPattern[],
  allowedRoots: string[],
  workerScriptPath: string,
  homedir: string,
  userConfigDir: string,
  toolName: string
): Promise<FieldRecord> {
  const result = await scan(text, patterns, {
    maxPromptBytes: config.maxPromptBytes,
    patternTimeoutMs: config.tier1.patternTimeoutMs,
    allowlist: config.tier1.allowlist,
    workerScriptPath,
  });

  let combinedDetections: Detection[] = result.detections;
  const allMatched: Detection[] = [...result.detections];
  const allSuppressed: Detection[] = [...result.suppressed];
  let tier2Evidence: Tier2Evidence[] = [];

  if (result.timeouts.length > 0) {
    logOperationalEvents(config.logging, "tool_output_pattern_timeout", result.timeouts, homedir, userConfigDir);
  }

  if (config.gitleaks.enabled) {
    const gitleaksResult = scanWithGitleaks(text, config.gitleaks, allowedRoots, config.maxPromptBytes);
    if (gitleaksResult.errors.length > 0) {
      logOperationalEvents(config.logging, "tool_output_gitleaks_error", gitleaksResult.errors, homedir, userConfigDir);
    }
    const allowlistFiltered = gitleaksResult.detections.filter((d) => !isAllowlisted(d.matchedText, config.tier1.allowlist));
    const allowlistSuppressed = gitleaksResult.detections.filter((d) => isAllowlisted(d.matchedText, config.tier1.allowlist));
    allMatched.push(...allowlistFiltered);
    allSuppressed.push(...allowlistSuppressed);
    combinedDetections = dedupeDetections([...combinedDetections, ...allowlistFiltered]);
  }

  let tier2RequestFailed = false;
  if (config.tier2.enabled) {
    if (!isLocalHostname(config.tier2.ollamaUrl) && config.tier2.allowNonLocal) {
      logOperationalEvents(
        config.logging,
        "tool_output_tier2_nonlocal_warning",
        [`tier2.ollamaUrl "${config.tier2.ollamaUrl}" is non-local and allowNonLocal is true — ${toolName} output is leaving this host.`],
        homedir,
        userConfigDir
      );
    }
    const tier2Outcome = await callOllama(text, config.tier2, config.maxPromptBytes);
    if (tier2Outcome.kind === "skipped") {
      logOperationalEvents(config.logging, "tool_output_tier2_skipped", [tier2Outcome.reason], homedir, userConfigDir);
    } else if (tier2Outcome.kind === "failed") {
      tier2RequestFailed = true;
      logOperationalEvents(config.logging, "tool_output_tier2_failed", [tier2Outcome.reason], homedir, userConfigDir);
    } else {
      tier2Evidence = tier2Outcome.evidence;
      if (tier2Outcome.detections.length > 0) {
        allMatched.push(...tier2Outcome.detections);
        combinedDetections = dedupeDetections([...combinedDetections, ...tier2Outcome.detections]);
      }
    }
  }

  const fieldDecision = decide(config.mode, combinedDetections, tier2RequestFailed);
  return { field, text, detections: combinedDetections, decision: fieldDecision, allMatched, allSuppressed, tier2Evidence };
}

function highestPrecedence(records: FieldRecord[]): "allow" | "warn" | "block" {
  if (records.some((r) => r.decision === "block")) return "block";
  if (records.some((r) => r.decision === "warn")) return "warn";
  return "allow";
}

async function main(): Promise<void> {
  const homedir = os.homedir();
  const pluginRoot = path.resolve(__dirname, "..", "..");
  const workerScriptPath = path.join(__dirname, "pattern-worker.js");

  const raw = readStdin();
  let payload: HookPayload = {};
  try {
    payload = raw.trim() ? JSON.parse(raw) : {};
  } catch {
    payload = {};
  }

  const toolName = typeof payload.tool_name === "string" ? payload.tool_name : "";
  const projectRoot = typeof payload.cwd === "string" ? payload.cwd : process.cwd();

  if (toolName !== "Read" && toolName !== "Grep" && toolName !== "Bash") {
    emitAllow();
    return;
  }

  const { config, userConfigDir, errors: configErrors } = loadConfig(pluginRoot, projectRoot, homedir);
  const allowedRoots = [pluginRoot, userConfigDir, projectRoot];

  if (!config.toolOutput.enabled || !config.toolOutput.tools.includes(toolName)) {
    emitAllow();
    return;
  }

  const fields = extractScannableFields(toolName, payload.tool_response);
  if (fields.length === 0) {
    emitAllow();
    return;
  }

  try {
    const { patterns, loadErrors } = loadPatterns(pluginRoot, config.tier1, allowedRoots);
    if (configErrors.length > 0) {
      logOperationalEvents(config.logging, "tool_output_config_error", configErrors, homedir, userConfigDir);
    }
    if (loadErrors.length > 0) {
      logOperationalEvents(config.logging, "tool_output_pattern_load_error", loadErrors, homedir, userConfigDir);
    }

    const records: FieldRecord[] = [];
    for (const f of fields) {
      records.push(
        await evaluateField(f.text, f.field, config, patterns, allowedRoots, workerScriptPath, homedir, userConfigDir, toolName)
      );
    }

    for (const record of records) {
      if (record.detections.length > 0) {
        logDetections(config.logging, config.mode, record.detections, homedir, userConfigDir, {
          channel: "tool_output",
          tool: toolName,
        });
      }
      if (config.feedback.enabled) {
        const statsWarning = recordPatternActivity(record.allMatched, record.allSuppressed, userConfigDir).warning;
        if (statsWarning) process.stderr.write(`${statsWarning}\n`);
        const feedbackWarning = logFeedback(config.logging, config.feedback, record.tier2Evidence, homedir, userConfigDir).warning;
        if (feedbackWarning) process.stderr.write(`${feedbackWarning}\n`);
      }
    }

    const overall = highestPrecedence(records);

    if (overall === "block") {
      const blockRecords = records.filter((r) => r.decision === "block");
      const replacements = new Map<ScanField, string>();
      for (const record of blockRecords) {
        if (record.detections.length > 0) {
          const redaction = redactByOffsets(record.text, record.detections, placeholderFor);
          replacements.set(record.field, redaction.fullyVerifiable ? redaction.text : FULL_FIELD_PLACEHOLDER);
        } else {
          // decide() only returns "block" with zero detections on unresolved risk
          // (a Tier 2 request failure) — fail closed on the whole field (D23).
          replacements.set(record.field, FULL_FIELD_PLACEHOLDER);
        }
      }
      const updatedToolOutput = rebuildToolResponse(payload.tool_response, replacements);
      const reason = buildReason(toolName, "blocked", blockRecords, config);
      process.stdout.write(
        JSON.stringify({
          decision: "block",
          reason,
          hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput },
        })
      );
      process.exitCode = 0;
      return;
    }

    if (overall === "warn") {
      const warnRecords = records.filter((r) => r.decision === "warn");
      const additionalContext = buildReason(toolName, "flagged", warnRecords, config);
      process.stdout.write(
        JSON.stringify({ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext } })
      );
      process.exitCode = 0;
      return;
    }

    emitAllow();
  } finally {
    shutdownPatternWorker();
  }
}

void main();
