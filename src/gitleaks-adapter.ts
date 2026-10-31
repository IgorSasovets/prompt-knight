import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { spawnSync } from "child_process";
import { Detection, GitleaksConfig } from "./types";
import { resolveSandboxedPath } from "./config-loader";
import { truncateToByteLimit } from "./tier1-engine";

export interface GitleaksScanResult {
  detections: Detection[];
  errors: string[];
}

interface GitleaksFinding {
  RuleID?: string;
  Secret?: string;
  Match?: string;
}

const WINDOWS_EXECUTABLE_SUFFIXES = ["", ".exe", ".cmd", ".bat"];

/**
 * Node has no built-in `which`. A bare command name (the default, "gitleaks") is
 * searched across PATH; a value containing a path separator or an absolute path is
 * used literally. This is binary *discovery*, not path sandboxing — the binary
 * legitimately lives outside the plugin/user/project dirs (e.g. a Homebrew prefix),
 * so REQ-CFG-02's sandboxing doesn't apply here. Integrity is enforced separately by
 * verifyBinary()'s hash + version check (TM-7).
 */
export function resolveBinaryPath(configuredPath: string): string | null {
  if (configuredPath.includes(path.sep) || path.isAbsolute(configuredPath)) {
    return fs.existsSync(configuredPath) ? configuredPath : null;
  }

  const pathEnv = process.env.PATH ?? "";
  const dirs = pathEnv.split(path.delimiter).filter(Boolean);
  const suffixes = process.platform === "win32" ? WINDOWS_EXECUTABLE_SUFFIXES : [""];

  for (const dir of dirs) {
    for (const suffix of suffixes) {
      const candidate = path.join(dir, `${configuredPath}${suffix}`);
      if (fs.existsSync(candidate)) return candidate;
    }
  }
  return null;
}

function sha256OfFile(filePath: string): string {
  const data = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(data).digest("hex");
}

function normalizeVersion(v: string): string {
  return v.trim().replace(/^v/i, "");
}

export interface VerifyResult {
  ok: boolean;
  resolvedPath?: string;
  reason?: string;
}

/**
 * Verifies the configured gitleaks binary against BOTH the pinned version and the
 * expected SHA-256 checksum before it is ever invoked (REQ-GL-03, REQ-SEC-07, TM-7).
 * Either check missing or failing means "not verified" — the caller must then take
 * the REQ-GL-04 skip-and-continue path, never run an unverified binary.
 */
export function verifyBinary(config: GitleaksConfig): VerifyResult {
  const resolvedPath = resolveBinaryPath(config.binaryPath);
  if (!resolvedPath) {
    return {
      ok: false,
      reason:
        `gitleaks binary not found (configured path: "${config.binaryPath}"). ` +
        "Run `node dist/src/gitleaks-installer.js` to download and verify a pinned build automatically, " +
        "or install gitleaks yourself and configure gitleaks.binaryPath/pinnedVersion/expectedSha256.",
    };
  }

  if (!config.expectedSha256) {
    return {
      ok: false,
      reason:
        "gitleaks.expectedSha256 is not configured — refusing to run an unverified binary. " +
        `Compute it with: shasum -a 256 "${resolvedPath}" (or certutil -hashfile "${resolvedPath}" SHA256 on Windows), ` +
        "then set gitleaks.pinnedVersion and gitleaks.expectedSha256 in your config.",
    };
  }

  let actualHash: string;
  try {
    actualHash = sha256OfFile(resolvedPath);
  } catch (err) {
    return { ok: false, reason: `failed to read gitleaks binary for verification: ${(err as Error).message}` };
  }
  if (actualHash.toLowerCase() !== config.expectedSha256.toLowerCase()) {
    return { ok: false, reason: `gitleaks binary checksum mismatch (expected ${config.expectedSha256}, got ${actualHash})` };
  }

  const versionResult = spawnSync(resolvedPath, ["version"], { timeout: 5000, shell: false, encoding: "utf8" });
  if (versionResult.error || versionResult.status !== 0) {
    return { ok: false, reason: `failed to run "${resolvedPath} version" for verification` };
  }
  const reportedVersion = normalizeVersion(versionResult.stdout || versionResult.stderr || "");
  const expectedVersion = normalizeVersion(config.pinnedVersion);
  if (!reportedVersion.includes(expectedVersion) || expectedVersion === "") {
    return {
      ok: false,
      reason: `gitleaks version mismatch (expected "${config.pinnedVersion}", got "${reportedVersion || "unknown"}")`,
    };
  }

  return { ok: true, resolvedPath };
}

function mapFindingsToDetections(findings: GitleaksFinding[], originalText: string): Detection[] {
  return findings.map((finding) => {
    const matchedText = finding.Secret || finding.Match || "";
    const index = matchedText ? originalText.indexOf(matchedText) : -1;
    return {
      category: finding.RuleID || "gitleaks_unknown",
      source: "gitleaks" as const,
      patternId: `gitleaks:${finding.RuleID || "unknown"}`,
      index: index >= 0 ? index : 0,
      length: matchedText.length,
      matchedText,
    };
  });
}

/**
 * Runs gitleaks against `text` as a supplementary Tier-1 check (REQ-GL-01/02). Never
 * throws: any failure (absent, unverified, spawn error, timeout, bad report) results
 * in an empty detection set plus a logged error, and built-in Tier 1 patterns continue
 * to enforce normally (REQ-GL-04) — this is an unconditional skip-and-continue, unlike
 * Tier 2's mode-dependent failure posture.
 *
 * gitleaks' `stdin` subcommand cannot emit a JSON report (confirmed from its own
 * source), so the prompt text is written to a short-lived temp file and scanned with
 * `gitleaks dir`, which does support --report-format/--report-path. The temp directory
 * is always removed afterward, even on failure.
 */
export function scanWithGitleaks(
  text: string,
  config: GitleaksConfig,
  allowedRoots: string[],
  maxPromptBytes: number
): GitleaksScanResult {
  const errors: string[] = [];
  const bounded = truncateToByteLimit(text, maxPromptBytes);
  const verify = verifyBinary(config);
  if (!verify.ok || !verify.resolvedPath) {
    errors.push(verify.reason ?? "gitleaks verification failed");
    return { detections: [], errors };
  }

  let configArgPath: string | null = null;
  if (config.configPath) {
    configArgPath = resolveSandboxedPath(config.configPath, allowedRoots[0] ?? process.cwd(), allowedRoots, "gitleaks.configPath", errors);
    if (!configArgPath) {
      // resolveSandboxedPath already pushed a "Refusing..." error — proceed without --config.
    }
  }

  let tmpDir: string | null = null;
  try {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "promptknight-gitleaks-"));
    const targetFile = path.join(tmpDir, "prompt.txt");
    const reportFile = path.join(tmpDir, "report.json");
    fs.writeFileSync(targetFile, bounded, { mode: 0o600 });

    const args = ["dir", targetFile, "--report-format", "json", "--report-path", reportFile, "--exit-code", "0", "--no-color"];
    if (configArgPath) {
      args.push("--config", configArgPath);
    }

    const result = spawnSync(verify.resolvedPath, args, {
      timeout: config.timeoutMs,
      shell: false,
      encoding: "utf8",
    });

    if (result.error) {
      errors.push(`gitleaks invocation failed: ${result.error.message}`);
      return { detections: [], errors };
    }

    if (!fs.existsSync(reportFile)) {
      if (result.status !== 0) {
        errors.push(`gitleaks exited with status ${result.status}: ${(result.stderr || "").slice(0, 500)}`);
      }
      // No report file and a clean exit means "nothing to report" — not an error.
      return { detections: [], errors };
    }

    let findings: GitleaksFinding[];
    try {
      const raw = fs.readFileSync(reportFile, "utf8");
      findings = raw.trim() ? JSON.parse(raw) : [];
      if (!Array.isArray(findings)) throw new Error("report is not a JSON array");
    } catch (err) {
      errors.push(`failed to parse gitleaks report: ${(err as Error).message}`);
      return { detections: [], errors };
    }

    return { detections: mapFindingsToDetections(findings, bounded), errors };
  } catch (err) {
    errors.push(`gitleaks scan failed: ${(err as Error).message}`);
    return { detections: [], errors };
  } finally {
    if (tmpDir) {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // best-effort cleanup — never let a cleanup failure surface as a scan error
      }
    }
  }
}
