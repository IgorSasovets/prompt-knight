"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveBinaryPath = resolveBinaryPath;
exports.verifyBinary = verifyBinary;
exports.scanWithGitleaks = scanWithGitleaks;
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const child_process_1 = require("child_process");
const config_loader_1 = require("./config-loader");
const WINDOWS_EXECUTABLE_SUFFIXES = ["", ".exe", ".cmd", ".bat"];
/**
 * Node has no built-in `which`. A bare command name (the default, "gitleaks") is
 * searched across PATH; a value containing a path separator or an absolute path is
 * used literally. This is binary *discovery*, not path sandboxing — the binary
 * legitimately lives outside the plugin/user/project dirs (e.g. a Homebrew prefix),
 * so REQ-CFG-02's sandboxing doesn't apply here. Integrity is enforced separately by
 * verifyBinary()'s hash + version check (TM-7).
 */
function resolveBinaryPath(configuredPath) {
    if (configuredPath.includes(path.sep) || path.isAbsolute(configuredPath)) {
        return fs.existsSync(configuredPath) ? configuredPath : null;
    }
    const pathEnv = process.env.PATH ?? "";
    const dirs = pathEnv.split(path.delimiter).filter(Boolean);
    const suffixes = process.platform === "win32" ? WINDOWS_EXECUTABLE_SUFFIXES : [""];
    for (const dir of dirs) {
        for (const suffix of suffixes) {
            const candidate = path.join(dir, `${configuredPath}${suffix}`);
            if (fs.existsSync(candidate))
                return candidate;
        }
    }
    return null;
}
function sha256OfFile(filePath) {
    const data = fs.readFileSync(filePath);
    return crypto.createHash("sha256").update(data).digest("hex");
}
function normalizeVersion(v) {
    return v.trim().replace(/^v/i, "");
}
/**
 * Verifies the configured gitleaks binary against BOTH the pinned version and the
 * expected SHA-256 checksum before it is ever invoked (REQ-GL-03, REQ-SEC-07, TM-7).
 * Either check missing or failing means "not verified" — the caller must then take
 * the REQ-GL-04 skip-and-continue path, never run an unverified binary.
 */
function verifyBinary(config) {
    const resolvedPath = resolveBinaryPath(config.binaryPath);
    if (!resolvedPath) {
        return { ok: false, reason: `gitleaks binary not found (configured path: "${config.binaryPath}")` };
    }
    if (!config.expectedSha256) {
        return {
            ok: false,
            reason: "gitleaks.expectedSha256 is not configured — refusing to run an unverified binary. " +
                `Compute it with: shasum -a 256 "${resolvedPath}" (or certutil -hashfile "${resolvedPath}" SHA256 on Windows), ` +
                "then set gitleaks.pinnedVersion and gitleaks.expectedSha256 in your config.",
        };
    }
    let actualHash;
    try {
        actualHash = sha256OfFile(resolvedPath);
    }
    catch (err) {
        return { ok: false, reason: `failed to read gitleaks binary for verification: ${err.message}` };
    }
    if (actualHash.toLowerCase() !== config.expectedSha256.toLowerCase()) {
        return { ok: false, reason: `gitleaks binary checksum mismatch (expected ${config.expectedSha256}, got ${actualHash})` };
    }
    const versionResult = (0, child_process_1.spawnSync)(resolvedPath, ["version"], { timeout: 5000, shell: false, encoding: "utf8" });
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
function mapFindingsToDetections(findings, originalText) {
    return findings.map((finding) => {
        const matchedText = finding.Secret || finding.Match || "";
        const index = matchedText ? originalText.indexOf(matchedText) : -1;
        return {
            category: finding.RuleID || "gitleaks_unknown",
            source: "gitleaks",
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
function scanWithGitleaks(text, config, allowedRoots) {
    const errors = [];
    const verify = verifyBinary(config);
    if (!verify.ok || !verify.resolvedPath) {
        errors.push(verify.reason ?? "gitleaks verification failed");
        return { detections: [], errors };
    }
    let configArgPath = null;
    if (config.configPath) {
        configArgPath = (0, config_loader_1.resolveSandboxedPath)(config.configPath, allowedRoots[0] ?? process.cwd(), allowedRoots, "gitleaks.configPath", errors);
        if (!configArgPath) {
            // resolveSandboxedPath already pushed a "Refusing..." error — proceed without --config.
        }
    }
    let tmpDir = null;
    try {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "promptknight-gitleaks-"));
        const targetFile = path.join(tmpDir, "prompt.txt");
        const reportFile = path.join(tmpDir, "report.json");
        fs.writeFileSync(targetFile, text, { mode: 0o600 });
        const args = ["dir", targetFile, "--report-format", "json", "--report-path", reportFile, "--exit-code", "0", "--no-color"];
        if (configArgPath) {
            args.push("--config", configArgPath);
        }
        const result = (0, child_process_1.spawnSync)(verify.resolvedPath, args, {
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
        let findings;
        try {
            const raw = fs.readFileSync(reportFile, "utf8");
            findings = raw.trim() ? JSON.parse(raw) : [];
            if (!Array.isArray(findings))
                throw new Error("report is not a JSON array");
        }
        catch (err) {
            errors.push(`failed to parse gitleaks report: ${err.message}`);
            return { detections: [], errors };
        }
        return { detections: mapFindingsToDetections(findings, text), errors };
    }
    catch (err) {
        errors.push(`gitleaks scan failed: ${err.message}`);
        return { detections: [], errors };
    }
    finally {
        if (tmpDir) {
            try {
                fs.rmSync(tmpDir, { recursive: true, force: true });
            }
            catch {
                // best-effort cleanup — never let a cleanup failure surface as a scan error
            }
        }
    }
}
