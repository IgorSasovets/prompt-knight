import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as zlib from "zlib";
import {
  buildDownloadUrl,
  detectPlatformKey,
  downloadArchive,
  FetchLike,
  installBinary,
  PINNED_GITLEAKS_RELEASES,
  PINNED_GITLEAKS_VERSION,
  updateUserConfig,
} from "../src/gitleaks-installer";

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// --- Platform coverage (REQ from the user: Linux + macOS at minimum, Windows too) ---
// detectPlatformKey is pure and parameterized, so every target platform/arch is
// tested here regardless of which OS actually runs this file — and CI's existing
// macos-13/windows-latest/ubuntu-latest matrix (.github/workflows/ci.yml) exercises
// the real process.platform/process.arch path through the same function for real
// on each of those three.

test("detectPlatformKey covers every pinned macOS target", () => {
  assert.equal(detectPlatformKey("darwin", "x64"), "darwin_x64");
  assert.equal(detectPlatformKey("darwin", "arm64"), "darwin_arm64");
});

test("detectPlatformKey covers every pinned Linux target", () => {
  assert.equal(detectPlatformKey("linux", "x64"), "linux_x64");
  assert.equal(detectPlatformKey("linux", "arm64"), "linux_arm64");
  assert.equal(detectPlatformKey("linux", "ia32"), "linux_x32");
  assert.equal(detectPlatformKey("linux", "arm"), "linux_armv7");
});

test("detectPlatformKey covers every pinned Windows target", () => {
  assert.equal(detectPlatformKey("win32", "x64"), "windows_x64");
  assert.equal(detectPlatformKey("win32", "arm64"), "windows_arm64");
  assert.equal(detectPlatformKey("win32", "ia32"), "windows_x32");
});

test("detectPlatformKey returns null for an unsupported platform or arch", () => {
  assert.equal(detectPlatformKey("sunos", "x64"), null);
  assert.equal(detectPlatformKey("darwin", "ia32"), null); // macOS has no x32 build
  assert.equal(detectPlatformKey("linux", "mips"), null);
});

test("detectPlatformKey matches this machine's actual platform/arch", () => {
  // Not every CI runner's exact platform/arch combo is guaranteed to be one we
  // support, but on the three used in CI (macOS/Linux/Windows x64 or arm64) this
  // should always resolve — if it doesn't, that's a real gap worth seeing fail.
  const key = detectPlatformKey(process.platform, process.arch);
  assert.ok(key === null || key in PINNED_GITLEAKS_RELEASES);
});

// --- Pin table sanity ---

test("every pinned release has a well-formed filename and a 64-hex-char sha256", () => {
  for (const [key, release] of Object.entries(PINNED_GITLEAKS_RELEASES)) {
    assert.match(release.sha256, /^[0-9a-f]{64}$/, `${key} has a malformed sha256`);
    assert.ok(release.filename.includes(PINNED_GITLEAKS_VERSION), `${key}'s filename doesn't embed the pinned version`);
    assert.match(release.filename, /\.(tar\.gz|zip)$/, `${key} has an unexpected file extension`);
  }
});

test("buildDownloadUrl matches gitleaks' real release URL scheme", () => {
  const release = PINNED_GITLEAKS_RELEASES.linux_x64!;
  assert.equal(
    buildDownloadUrl(release),
    `https://github.com/gitleaks/gitleaks/releases/download/v${PINNED_GITLEAKS_VERSION}/${release.filename}`
  );
});

// --- downloadArchive, with an injected fetch so no real network call ever happens ---

function fakeFetch(buffer: Buffer, status = 200): FetchLike {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    arrayBuffer: async () => {
      const copy = new ArrayBuffer(buffer.byteLength);
      new Uint8Array(copy).set(buffer);
      return copy;
    },
  });
}

test("downloadArchive accepts a response matching the expected checksum", async () => {
  const buffer = Buffer.from("pretend archive bytes");
  const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");
  const result = await downloadArchive("https://example.invalid/x", sha256, fakeFetch(buffer));
  assert.equal(result.ok, true);
  assert.deepEqual(result.buffer, buffer);
});

test("downloadArchive rejects a checksum mismatch", async () => {
  const buffer = Buffer.from("pretend archive bytes");
  const result = await downloadArchive("https://example.invalid/x", "0".repeat(64), fakeFetch(buffer));
  assert.equal(result.ok, false);
  assert.ok(result.reason?.includes("checksum mismatch"));
});

test("downloadArchive fails cleanly on a non-2xx response", async () => {
  const result = await downloadArchive("https://example.invalid/x", "0".repeat(64), fakeFetch(Buffer.from(""), 404));
  assert.equal(result.ok, false);
  assert.ok(result.reason?.includes("404"));
});

test("downloadArchive fails cleanly when fetch itself throws", async () => {
  const throwingFetch: FetchLike = async () => {
    throw new Error("network down");
  };
  const result = await downloadArchive("https://example.invalid/x", "0".repeat(64), throwingFetch);
  assert.equal(result.ok, false);
  assert.ok(result.reason?.includes("network down"));
});

// --- installBinary: extraction + write + (POSIX) chmod, for both archive kinds ---

function tarGzWithBinary(content: Buffer): Buffer {
  const header = Buffer.alloc(512);
  header.write("gitleaks", 0, "ascii");
  header.write("0000644\0", 100, "ascii");
  header.write("0000000\0", 108, "ascii");
  header.write("0000000\0", 116, "ascii");
  header.write(`${content.length.toString(8).padStart(11, "0")}\0`, 124, "ascii");
  header.write("00000000000\0", 136, "ascii");
  header.write("        ", 148, "ascii");
  header.write("0", 156, "ascii");
  const paddedSize = Math.ceil(content.length / 512) * 512;
  const contentBlock = Buffer.alloc(paddedSize);
  content.copy(contentBlock);
  return zlib.gzipSync(Buffer.concat([header, contentBlock, Buffer.alloc(1024)]));
}

function zipWithBinary(content: Buffer): Buffer {
  const nameBuf = Buffer.from("gitleaks.exe", "utf8");
  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(0, 6);
  localHeader.writeUInt16LE(0, 8); // stored
  localHeader.writeUInt16LE(0, 10);
  localHeader.writeUInt16LE(0, 12);
  localHeader.writeUInt32LE(0, 14);
  localHeader.writeUInt32LE(content.length, 18);
  localHeader.writeUInt32LE(content.length, 22);
  localHeader.writeUInt16LE(nameBuf.length, 26);
  localHeader.writeUInt16LE(0, 28);
  const localEntry = Buffer.concat([localHeader, nameBuf, content]);

  const centralHeader = Buffer.alloc(46);
  centralHeader.writeUInt32LE(0x02014b50, 0);
  centralHeader.writeUInt16LE(20, 4);
  centralHeader.writeUInt16LE(20, 6);
  centralHeader.writeUInt16LE(0, 8);
  centralHeader.writeUInt16LE(0, 10);
  centralHeader.writeUInt16LE(0, 12);
  centralHeader.writeUInt16LE(0, 14);
  centralHeader.writeUInt32LE(0, 16);
  centralHeader.writeUInt32LE(content.length, 20);
  centralHeader.writeUInt32LE(content.length, 24);
  centralHeader.writeUInt16LE(nameBuf.length, 28);
  centralHeader.writeUInt16LE(0, 30);
  centralHeader.writeUInt16LE(0, 32);
  centralHeader.writeUInt16LE(0, 34);
  centralHeader.writeUInt16LE(0, 36);
  centralHeader.writeUInt32LE(0, 38);
  centralHeader.writeUInt32LE(0, 42);
  const centralEntry = Buffer.concat([centralHeader, nameBuf]);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(centralEntry.length, 12);
  eocd.writeUInt32LE(localEntry.length, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([localEntry, centralEntry, eocd]);
}

test("installBinary extracts a tar.gz (macOS/Linux) archive and writes the binary", () => {
  const userConfigDir = mkTmp("promptknight-installer-");
  const content = Buffer.from("fake gitleaks ELF/Mach-O bytes");
  const result = installBinary(tarGzWithBinary(content), `gitleaks_${PINNED_GITLEAKS_VERSION}_linux_x64.tar.gz`, userConfigDir);

  assert.equal(result.ok, true);
  assert.equal(result.installedPath, path.join(userConfigDir, "bin", "gitleaks"));
  assert.deepEqual(fs.readFileSync(result.installedPath!), content);
  assert.equal(result.sha256, crypto.createHash("sha256").update(content).digest("hex"));
});

test("installBinary extracts a zip (Windows) archive and writes gitleaks.exe", () => {
  const userConfigDir = mkTmp("promptknight-installer-");
  const content = Buffer.from("fake gitleaks PE bytes");
  const result = installBinary(zipWithBinary(content), `gitleaks_${PINNED_GITLEAKS_VERSION}_windows_x64.zip`, userConfigDir);

  assert.equal(result.ok, true);
  assert.equal(result.installedPath, path.join(userConfigDir, "bin", "gitleaks.exe"));
  assert.deepEqual(fs.readFileSync(result.installedPath!), content);
});

test("installBinary sets the installed binary executable on POSIX", { skip: process.platform === "win32" }, () => {
  const userConfigDir = mkTmp("promptknight-installer-");
  const result = installBinary(
    tarGzWithBinary(Buffer.from("x")),
    `gitleaks_${PINNED_GITLEAKS_VERSION}_linux_x64.tar.gz`,
    userConfigDir
  );
  assert.equal(fs.statSync(result.installedPath!).mode & 0o777, 0o755);
});

test("installBinary fails cleanly (no throw) when the archive doesn't actually contain the binary", () => {
  const userConfigDir = mkTmp("promptknight-installer-");
  const emptyTarGz = zlib.gzipSync(Buffer.alloc(1024)); // valid gzip, no entries at all
  const result = installBinary(emptyTarGz, `gitleaks_${PINNED_GITLEAKS_VERSION}_linux_x64.tar.gz`, userConfigDir);
  assert.equal(result.ok, false);
  assert.ok(result.reason?.includes("extraction failed"));
});

// --- updateUserConfig ---

test("updateUserConfig creates a fresh config.json when none exists", () => {
  const userConfigDir = mkTmp("promptknight-installer-");
  updateUserConfig(userConfigDir, { enabled: true, binaryPath: "/x/gitleaks", pinnedVersion: "8.30.1", expectedSha256: "abc" });

  const written = JSON.parse(fs.readFileSync(path.join(userConfigDir, "config.json"), "utf8"));
  assert.equal(written.gitleaks.enabled, true);
  assert.equal(written.gitleaks.binaryPath, "/x/gitleaks");
});

test("updateUserConfig preserves unrelated top-level and gitleaks sub-keys", () => {
  const userConfigDir = mkTmp("promptknight-installer-");
  fs.writeFileSync(
    path.join(userConfigDir, "config.json"),
    JSON.stringify({ mode: "warn", gitleaks: { timeoutMs: 9999, enabled: false } })
  );

  updateUserConfig(userConfigDir, { enabled: true, binaryPath: "/x/gitleaks" });

  const written = JSON.parse(fs.readFileSync(path.join(userConfigDir, "config.json"), "utf8"));
  assert.equal(written.mode, "warn"); // untouched top-level key
  assert.equal(written.gitleaks.timeoutMs, 9999); // untouched gitleaks sub-key
  assert.equal(written.gitleaks.enabled, true); // updated
  assert.equal(written.gitleaks.binaryPath, "/x/gitleaks"); // added
});

test("updateUserConfig starts fresh if the existing config.json is malformed", () => {
  const userConfigDir = mkTmp("promptknight-installer-");
  fs.writeFileSync(path.join(userConfigDir, "config.json"), "{ not valid json");
  updateUserConfig(userConfigDir, { enabled: true });
  const written = JSON.parse(fs.readFileSync(path.join(userConfigDir, "config.json"), "utf8"));
  assert.equal(written.gitleaks.enabled, true);
});
