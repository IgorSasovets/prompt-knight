#!/usr/bin/env node
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { loadConfig } from "./config-loader";
import { decide } from "./enforcement";
import { logDetections, logFeedback, logOperationalEvents } from "./feedback-logger";
import { scanWithGitleaks } from "./gitleaks-adapter";
import { recordPatternActivity } from "./pattern-stats";
import { dedupeDetections, isAllowlisted, loadPatterns, scan, shutdownPatternWorker } from "./tier1-engine";
import { callOllama, isLocalHostname, Tier2Evidence } from "./tier2-ollama";
import { Detection, Mode } from "./types";
import { redactPreview, sanitizeErrorForUser } from "./validation";

interface HookPayload {
  prompt?: unknown;
  cwd?: unknown;
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

function emitWarn(message: string): void {
  process.stdout.write(JSON.stringify({ systemMessage: message }));
  process.exitCode = 0;
}

function emitBlock(reason: string): void {
  process.stderr.write(reason);
  process.exitCode = 2;
}

function summarizeDetections(mode: Mode, categories: string[], previews: Array<string | undefined>): string {
  const uniqueCategories = Array.from(new Set(categories));
  const label = mode === "block" ? "blocked" : "flagged";
  const previewText = previews.some((p) => p !== undefined)
    ? ` (preview: ${previews.filter((p): p is string => p !== undefined).join(", ")})`
    : "";
  return `PromptKnight ${label} this prompt: possible ${uniqueCategories.join(", ")} detected${previewText}.`;
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

  const prompt = typeof payload.prompt === "string" ? payload.prompt : "";
  const projectRoot = typeof payload.cwd === "string" ? payload.cwd : process.cwd();

  if (prompt.length === 0) {
    emitAllow();
    return;
  }

  const { config, userConfigDir, errors: configErrors } = loadConfig(pluginRoot, projectRoot, homedir);
  const allowedRoots = [pluginRoot, userConfigDir, projectRoot];

  try {
    const { patterns, loadErrors } = loadPatterns(pluginRoot, config.tier1, allowedRoots);

    const result = await scan(prompt, patterns, {
      maxPromptBytes: config.maxPromptBytes,
      patternTimeoutMs: config.tier1.patternTimeoutMs,
      allowlist: config.tier1.allowlist,
      workerScriptPath,
    });

    let combinedDetections: Detection[] = result.detections;
    const allMatched: Detection[] = [...result.detections];
    const allSuppressed: Detection[] = [...result.suppressed];
    let tier2Evidence: Tier2Evidence[] = [];

    if (config.gitleaks.enabled) {
      const gitleaksResult = scanWithGitleaks(prompt, config.gitleaks, allowedRoots, config.maxPromptBytes);
      if (gitleaksResult.errors.length > 0) {
        logOperationalEvents(config.logging, "gitleaks_error", gitleaksResult.errors, homedir, userConfigDir);
      }
      const allowlistFiltered = gitleaksResult.detections.filter(
        (d) => !isAllowlisted(d.matchedText, config.tier1.allowlist)
      );
      const allowlistSuppressed = gitleaksResult.detections.filter((d) =>
        isAllowlisted(d.matchedText, config.tier1.allowlist)
      );
      allMatched.push(...allowlistFiltered);
      allSuppressed.push(...allowlistSuppressed);
      // Tier1 first so its more specific category name wins on a duplicate secret value.
      combinedDetections = dedupeDetections([...combinedDetections, ...allowlistFiltered]);
    }

    let tier2RequestFailed = false;
    if (config.tier2.enabled) {
      if (!isLocalHostname(config.tier2.ollamaUrl) && config.tier2.allowNonLocal) {
        logOperationalEvents(
          config.logging,
          "tier2_nonlocal_warning",
          [`tier2.ollamaUrl "${config.tier2.ollamaUrl}" is non-local and allowNonLocal is true — prompt content is leaving this host.`],
          homedir,
          userConfigDir
        );
      }

      const tier2Outcome = await callOllama(prompt, config.tier2, config.maxPromptBytes);
      if (tier2Outcome.kind === "skipped") {
        logOperationalEvents(config.logging, "tier2_skipped", [tier2Outcome.reason], homedir, userConfigDir);
      } else if (tier2Outcome.kind === "failed") {
        tier2RequestFailed = true;
        logOperationalEvents(config.logging, "tier2_failed", [tier2Outcome.reason], homedir, userConfigDir);
      } else {
        tier2Evidence = tier2Outcome.evidence;
        if (tier2Outcome.detections.length > 0) {
          allMatched.push(...tier2Outcome.detections);
          // Concatenated last: Tier 2 can only add detections, never remove tier1/gitleaks
          // ones (D9, REQ-T2-03) — escalate-only falls out of this ordering for free.
          combinedDetections = dedupeDetections([...combinedDetections, ...tier2Outcome.detections]);
        }
      }
    }

    if (config.feedback.enabled) {
      const statsWarning = recordPatternActivity(allMatched, allSuppressed, userConfigDir).warning;
      if (statsWarning) process.stderr.write(`${statsWarning}\n`);
      const feedbackWarning = logFeedback(config.logging, config.feedback, tier2Evidence, homedir, userConfigDir).warning;
      if (feedbackWarning) process.stderr.write(`${feedbackWarning}\n`);
    }

    if (configErrors.length > 0) {
      logOperationalEvents(config.logging, "config_error", configErrors, homedir, userConfigDir);
    }
    if (loadErrors.length > 0) {
      logOperationalEvents(config.logging, "pattern_load_error", loadErrors, homedir, userConfigDir);
    }
    if (result.timeouts.length > 0) {
      logOperationalEvents(config.logging, "pattern_timeout", result.timeouts, homedir, userConfigDir);
    }

    const logResult = logDetections(config.logging, config.mode, combinedDetections, homedir, userConfigDir);
    if (logResult.warning) {
      process.stderr.write(`${logResult.warning}\n`);
    }

    const decision = decide(config.mode, combinedDetections, tier2RequestFailed);

    if (decision === "block" || decision === "warn") {
      const message =
        combinedDetections.length === 0
          ? "PromptKnight could not complete semantic analysis (Tier 2) for this prompt, and the configured mode fails closed when a check can't run."
          : summarizeDetections(
              config.mode,
              combinedDetections.map((d) => d.category),
              combinedDetections.map((d) =>
                config.logging.redactValues ? redactPreview(d.matchedText, config.logging.previewChars) : undefined
              )
            );
      if (decision === "block") {
        emitBlock(message);
      } else {
        emitWarn(message);
      }
    } else {
      emitAllow();
    }
  } catch (err) {
    const decision = decide(config.mode, [], true);
    const message = sanitizeErrorForUser(err);
    if (decision === "block") {
      emitBlock(message);
    } else {
      emitWarn(message);
    }
  } finally {
    shutdownPatternWorker();
  }
}

void main();
