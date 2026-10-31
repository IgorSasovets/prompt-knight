#!/usr/bin/env node
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
exports.PINNED_GITLEAKS_RELEASES = exports.PINNED_GITLEAKS_VERSION = void 0;
exports.detectPlatformKey = detectPlatformKey;
exports.buildDownloadUrl = buildDownloadUrl;
exports.downloadArchive = downloadArchive;
exports.installBinary = installBinary;
exports.updateUserConfig = updateUserConfig;
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const readline = __importStar(require("readline"));
const archive_extract_1 = require("./archive-extract");
const config_loader_1 = require("./config-loader");
const gitleaks_adapter_1 = require("./gitleaks-adapter");
// Pinned to one specific gitleaks release. Bumping this means: fetch the real
// `gitleaks_<version>_checksums.txt` for the new version from
// https://github.com/gitleaks/gitleaks/releases, and replace every hash below —
// never invent one. This is the documented maintenance cost of the one, opt-in,
// explicitly-invoked auto-install path (see docs/security.md); the manual
// bring-your-own-binary path in gitleaks-adapter.ts is unaffected by this file.
exports.PINNED_GITLEAKS_VERSION = "8.30.1";
// Real values fetched from gitleaks' v8.30.1 release's own published
// gitleaks_8.30.1_checksums.txt — not invented.
exports.PINNED_GITLEAKS_RELEASES = {
    darwin_arm64: {
        filename: `gitleaks_${exports.PINNED_GITLEAKS_VERSION}_darwin_arm64.tar.gz`,
        sha256: "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
    },
    darwin_x64: {
        filename: `gitleaks_${exports.PINNED_GITLEAKS_VERSION}_darwin_x64.tar.gz`,
        sha256: "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    },
    linux_arm64: {
        filename: `gitleaks_${exports.PINNED_GITLEAKS_VERSION}_linux_arm64.tar.gz`,
        sha256: "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    },
    linux_armv7: {
        filename: `gitleaks_${exports.PINNED_GITLEAKS_VERSION}_linux_armv7.tar.gz`,
        sha256: "8d39f0d94ba0d774b2282187656fb039a2d82893ec1fd6be7d7121aae759a57d",
    },
    linux_x32: {
        filename: `gitleaks_${exports.PINNED_GITLEAKS_VERSION}_linux_x32.tar.gz`,
        sha256: "a87ba11adab22b4d6c6ea28b2da60f09154d5c2fdb44d4b07015d1e0433daecb",
    },
    linux_x64: {
        filename: `gitleaks_${exports.PINNED_GITLEAKS_VERSION}_linux_x64.tar.gz`,
        sha256: "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    },
    windows_arm64: {
        filename: `gitleaks_${exports.PINNED_GITLEAKS_VERSION}_windows_arm64.zip`,
        sha256: "b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f",
    },
    windows_x32: {
        filename: `gitleaks_${exports.PINNED_GITLEAKS_VERSION}_windows_x32.zip`,
        sha256: "190ad53db301eec3e90afe3a1a75270768b8ebf89e731345e19421c32c1ae1a1",
    },
    windows_x64: {
        filename: `gitleaks_${exports.PINNED_GITLEAKS_VERSION}_windows_x64.zip`,
        sha256: "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
    },
};
/**
 * Maps Node's `process.platform`/`process.arch` to gitleaks' release-asset naming.
 * Pure and parameterized (not reading `process.*` itself) specifically so every
 * platform/arch combination — including the two this dev machine isn't — can be
 * unit-tested from anywhere, and so the real mapping is exercised for real on each
 * OS in CI's macOS/Linux/Windows matrix.
 *
 * `linux`+`arm` is mapped to `linux_armv7` — Node's `arch` value doesn't distinguish
 * armv6 from armv7, and armv7 is the more common modern target; armv6 support is a
 * documented gap, not a silent one.
 */
function detectPlatformKey(platform, arch) {
    const archMap = { x64: "x64", arm64: "arm64", ia32: "x32", arm: "armv7" };
    const mappedArch = archMap[arch];
    if (!mappedArch)
        return null;
    const osMap = { darwin: "darwin", linux: "linux", win32: "windows" };
    const mappedOs = osMap[platform];
    if (!mappedOs)
        return null;
    const key = `${mappedOs}_${mappedArch}`;
    return key in exports.PINNED_GITLEAKS_RELEASES ? key : null;
}
function buildDownloadUrl(release) {
    return `https://github.com/gitleaks/gitleaks/releases/download/v${exports.PINNED_GITLEAKS_VERSION}/${release.filename}`;
}
/**
 * Downloads a release archive and verifies it against the pinned SHA-256 before
 * returning it. `fetchImpl` defaults to the global `fetch` but is injectable so
 * tests never make a real network call (same dependency-injection approach as
 * Phase 3's design, just without needing a subprocess or a stub server here).
 */
async function downloadArchive(url, expectedSha256, fetchImpl = fetch, timeoutMs = 30000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetchImpl(url, { signal: controller.signal });
        if (!response.ok) {
            return { ok: false, reason: `download failed with HTTP ${response.status}` };
        }
        const buffer = Buffer.from(await response.arrayBuffer());
        const actualSha256 = crypto.createHash("sha256").update(buffer).digest("hex");
        if (actualSha256.toLowerCase() !== expectedSha256.toLowerCase()) {
            return { ok: false, reason: `checksum mismatch (expected ${expectedSha256}, got ${actualSha256})` };
        }
        return { ok: true, buffer };
    }
    catch (err) {
        return { ok: false, reason: `download failed: ${err.message}` };
    }
    finally {
        clearTimeout(timer);
    }
}
/**
 * Extracts the gitleaks binary from a verified archive and writes it to
 * `<userConfigDir>/bin/gitleaks[.exe]`. The archive's own hash was already checked
 * by `downloadArchive()` (download integrity); this function computes a *second*,
 * separate hash — of the extracted binary itself — which is what gets pinned into
 * the user's config for every future at-rest tamper check by
 * `gitleaks-adapter.ts`'s `verifyBinary()`. These two hashes serve different
 * purposes and are deliberately not the same value.
 */
function installBinary(archiveBuffer, filename, userConfigDir) {
    const isZip = filename.endsWith(".zip");
    const binaryName = filename.includes("windows") ? "gitleaks.exe" : "gitleaks";
    let binary;
    try {
        binary = isZip ? (0, archive_extract_1.extractFileFromZip)(archiveBuffer, binaryName) : (0, archive_extract_1.extractFileFromTarGz)(archiveBuffer, binaryName);
    }
    catch (err) {
        return { ok: false, reason: `extraction failed: ${err.message}` };
    }
    const binDir = path.join(userConfigDir, "bin");
    const installedPath = path.join(binDir, binaryName);
    try {
        fs.mkdirSync(binDir, { recursive: true });
        fs.writeFileSync(installedPath, binary);
        if (process.platform !== "win32") {
            fs.chmodSync(installedPath, 0o755);
        }
    }
    catch (err) {
        return { ok: false, reason: `failed to write installed binary: ${err.message}` };
    }
    const sha256 = crypto.createHash("sha256").update(binary).digest("hex");
    return { ok: true, installedPath, sha256 };
}
/**
 * Read-merge-writes `~/.prompt-knight/config.json`'s `gitleaks` block, preserving
 * every other key the user already has there.
 */
function updateUserConfig(userConfigDir, gitleaksUpdate) {
    const configPath = path.join(userConfigDir, "config.json");
    let existing = {};
    try {
        if (fs.existsSync(configPath)) {
            const parsed = JSON.parse(fs.readFileSync(configPath, "utf8"));
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed))
                existing = parsed;
        }
    }
    catch {
        existing = {};
    }
    const existingGitleaks = (existing.gitleaks && typeof existing.gitleaks === "object" ? existing.gitleaks : {});
    existing.gitleaks = { ...existingGitleaks, ...gitleaksUpdate };
    fs.mkdirSync(userConfigDir, { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify(existing, null, 2));
}
async function confirm(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    try {
        const answer = await new Promise((resolve) => rl.question(question, resolve));
        return /^y(es)?$/i.test(answer.trim());
    }
    finally {
        rl.close();
    }
}
async function main() {
    const homedir = os.homedir();
    const userConfigDir = (0, config_loader_1.userConfigDirFor)(homedir);
    const existing = (0, gitleaks_adapter_1.resolveBinaryPath)("gitleaks");
    if (existing) {
        console.log(`gitleaks is already installed at ${existing}.`);
        console.log("If PromptKnight still won't use it, set gitleaks.pinnedVersion and gitleaks.expectedSha256 in your " +
            "config to match it (see docs/configuration.md), or re-run this installer to replace it with a " +
            `pinned, verified ${exports.PINNED_GITLEAKS_VERSION} build instead.`);
    }
    const platformKey = detectPlatformKey(process.platform, process.arch);
    if (!platformKey) {
        console.error(`Automatic install isn't supported for ${process.platform}/${process.arch}. ` +
            "Install gitleaks yourself (https://github.com/gitleaks/gitleaks#installing) and set " +
            "gitleaks.binaryPath/pinnedVersion/expectedSha256 in your config.");
        process.exitCode = 1;
        return;
    }
    const release = exports.PINNED_GITLEAKS_RELEASES[platformKey];
    const url = buildDownloadUrl(release);
    const proceed = await confirm(`Download and verify gitleaks v${exports.PINNED_GITLEAKS_VERSION} for ${platformKey} from ${url}? [y/N] `);
    if (!proceed) {
        console.log("Cancelled — nothing was downloaded or changed.");
        return;
    }
    console.log("Downloading and verifying checksum...");
    const download = await downloadArchive(url, release.sha256);
    if (!download.ok || !download.buffer) {
        console.error(`Download failed, nothing was installed: ${download.reason}`);
        process.exitCode = 1;
        return;
    }
    console.log("Checksum verified. Extracting and installing...");
    const install = installBinary(download.buffer, release.filename, userConfigDir);
    if (!install.ok || !install.installedPath || !install.sha256) {
        console.error(`Install failed: ${install.reason}`);
        process.exitCode = 1;
        return;
    }
    updateUserConfig(userConfigDir, {
        enabled: true,
        binaryPath: install.installedPath,
        pinnedVersion: exports.PINNED_GITLEAKS_VERSION,
        expectedSha256: install.sha256,
    });
    console.log(`Installed gitleaks ${exports.PINNED_GITLEAKS_VERSION} to ${install.installedPath}`);
    console.log(`Updated ${path.join(userConfigDir, "config.json")} — gitleaks is now enabled and verified.`);
}
if (require.main === module) {
    void main();
}
