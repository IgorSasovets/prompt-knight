import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { resolveBinaryPath, scanWithGitleaks, verifyBinary } from "../src/gitleaks-adapter";
import { GitleaksConfig } from "../src/types";

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function baseGitleaksConfig(overrides: Partial<GitleaksConfig> = {}): GitleaksConfig {
  return {
    enabled: true,
    binaryPath: "gitleaks",
    pinnedVersion: "8.x.y",
    expectedSha256: "",
    configPath: null,
    timeoutMs: 5000,
    ...overrides,
  };
}

/** A tiny fake "gitleaks" that just answers `version` deterministically, so the
 * hash+version verification path can be exercised without a real gitleaks install. */
function writeFakeBinary(dir: string, versionOutput: string): string {
  const scriptPath = path.join(dir, "fake-gitleaks");
  fs.writeFileSync(scriptPath, `#!/bin/sh\necho "${versionOutput}"\nexit 0\n`);
  fs.chmodSync(scriptPath, 0o755);
  return scriptPath;
}

function sha256(filePath: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

test("resolveBinaryPath: absolute path to an existing file resolves", () => {
  const dir = mkTmp("promptknight-gl-bin-");
  const file = writeFakeBinary(dir, "v1.2.3");
  assert.equal(resolveBinaryPath(file), file);
});

test("resolveBinaryPath: absolute path to a missing file returns null", () => {
  const dir = mkTmp("promptknight-gl-bin-");
  assert.equal(resolveBinaryPath(path.join(dir, "does-not-exist")), null);
});

test("resolveBinaryPath: bare command name is found on PATH", () => {
  const dir = mkTmp("promptknight-gl-path-");
  writeFakeBinary(dir, "v1.2.3");
  fs.renameSync(path.join(dir, "fake-gitleaks"), path.join(dir, "promptknight-fake-tool"));

  const originalPath = process.env.PATH;
  process.env.PATH = `${dir}${path.delimiter}${originalPath ?? ""}`;
  try {
    const resolved = resolveBinaryPath("promptknight-fake-tool");
    assert.equal(resolved, path.join(dir, "promptknight-fake-tool"));
  } finally {
    process.env.PATH = originalPath;
  }
});

test("resolveBinaryPath: bare command name not found anywhere returns null", () => {
  assert.equal(resolveBinaryPath("promptknight-definitely-not-a-real-tool"), null);
});

test("verifyBinary: succeeds when both hash and version match", { skip: process.platform === "win32" }, () => {
  const dir = mkTmp("promptknight-gl-verify-");
  const binary = writeFakeBinary(dir, "v8.30.1");
  const config = baseGitleaksConfig({ binaryPath: binary, pinnedVersion: "8.30.1", expectedSha256: sha256(binary) });
  const result = verifyBinary(config);
  assert.equal(result.ok, true);
  assert.equal(result.resolvedPath, binary);
});

test("verifyBinary: fails when expectedSha256 is not configured", () => {
  const dir = mkTmp("promptknight-gl-verify-");
  const binary = writeFakeBinary(dir, "v8.30.1");
  const config = baseGitleaksConfig({ binaryPath: binary, expectedSha256: "" });
  const result = verifyBinary(config);
  assert.equal(result.ok, false);
  assert.ok(result.reason?.includes("not configured"));
});

test("verifyBinary: fails on a checksum mismatch", () => {
  const dir = mkTmp("promptknight-gl-verify-");
  const binary = writeFakeBinary(dir, "v8.30.1");
  const config = baseGitleaksConfig({ binaryPath: binary, pinnedVersion: "8.30.1", expectedSha256: "0".repeat(64) });
  const result = verifyBinary(config);
  assert.equal(result.ok, false);
  assert.ok(result.reason?.includes("checksum mismatch"));
});

test("verifyBinary: fails on a version mismatch", { skip: process.platform === "win32" }, () => {
  const dir = mkTmp("promptknight-gl-verify-");
  const binary = writeFakeBinary(dir, "v8.30.1");
  const config = baseGitleaksConfig({ binaryPath: binary, pinnedVersion: "9.9.9", expectedSha256: sha256(binary) });
  const result = verifyBinary(config);
  assert.equal(result.ok, false);
  assert.ok(result.reason?.includes("version mismatch"));
});

test("verifyBinary: fails when the binary cannot be found at all", () => {
  const config = baseGitleaksConfig({ binaryPath: "/no/such/path/gitleaks" });
  const result = verifyBinary(config);
  assert.equal(result.ok, false);
  assert.ok(result.reason?.includes("not found"));
});

test("scanWithGitleaks: gracefully degrades (no throw, empty detections) when unverified", () => {
  const config = baseGitleaksConfig({ binaryPath: "/no/such/path/gitleaks" });
  const result = scanWithGitleaks("some prompt text", config, [process.cwd()]);
  assert.deepEqual(result.detections, []);
  assert.ok(result.errors.length > 0);
});

const realGitleaksPath = resolveBinaryPath("gitleaks");

test(
  "scanWithGitleaks: integration against a real gitleaks install",
  { skip: !realGitleaksPath ? "gitleaks is not installed on this machine's PATH" : false },
  () => {
    // This only runs when gitleaks is actually resolvable; the caller must still
    // configure a correct pinnedVersion/expectedSha256 for verification to pass, which
    // this test can't know in advance, so it only asserts the no-throw / cleanup
    // contract rather than a specific detection.
    const config = baseGitleaksConfig({ binaryPath: realGitleaksPath! });
    const result = scanWithGitleaks("hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX", config, [
      process.cwd(),
    ]);
    assert.ok(Array.isArray(result.detections));
    assert.ok(Array.isArray(result.errors));
  }
);
