#!/usr/bin/env node
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { loadConfig } from "./config-loader";
import { decide } from "./enforcement";
import { logDetections, logOperationalEvents } from "./feedback-logger";
import { scanWithGitleaks } from "./gitleaks-adapter";
import { dedupeDetections, isAllowlisted, loadPatterns, scan, shutdownPatternWorker } from "./tier1-engine";
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
    if (config.gitleaks.enabled) {
      const gitleaksResult = scanWithGitleaks(prompt, config.gitleaks, allowedRoots);
      if (gitleaksResult.errors.length > 0) {
        logOperationalEvents(config.logging, "gitleaks_error", gitleaksResult.errors, homedir, userConfigDir);
      }
      const allowlistFiltered = gitleaksResult.detections.filter(
        (d) => !isAllowlisted(d.matchedText, config.tier1.allowlist)
      );
      // Tier1 first so its more specific category name wins on a duplicate secret value.
      combinedDetections = dedupeDetections([...result.detections, ...allowlistFiltered]);
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

    const decision = decide(config.mode, combinedDetections, false);

    if (decision === "block") {
      const categories = combinedDetections.map((d) => d.category);
      const previews = combinedDetections.map((d) =>
        config.logging.redactValues ? redactPreview(d.matchedText, config.logging.previewChars) : undefined
      );
      emitBlock(summarizeDetections(config.mode, categories, previews));
    } else if (decision === "warn") {
      const categories = combinedDetections.map((d) => d.category);
      const previews = combinedDetections.map((d) =>
        config.logging.redactValues ? redactPreview(d.matchedText, config.logging.previewChars) : undefined
      );
      emitWarn(summarizeDetections(config.mode, categories, previews));
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
