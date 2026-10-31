import { test } from "node:test";
import assert from "node:assert/strict";
import * as zlib from "zlib";
import { extractFileFromTarGz, extractFileFromZip } from "../src/archive-extract";

// These round-trip tests build a small, valid archive entirely in memory with
// Node's own zlib (zero network, zero fixture files) and then extract it back —
// proving the hand-rolled readers work correctly, independent of which OS actually
// runs the test. Both formats are exercised unconditionally on every platform:
// gitleaks ships tar.gz for macOS/Linux and zip for Windows, and the whole point of
// testing this way is that the extraction logic for *all three* target OSes is
// verified for real here, not just whichever one happens to run the test.

function buildMinimalTarGz(fileName: string, content: Buffer): Buffer {
  const header = Buffer.alloc(512);
  header.write(fileName, 0, "ascii");
  header.write("0000644\0", 100, "ascii");
  header.write("0000000\0", 108, "ascii");
  header.write("0000000\0", 116, "ascii");
  header.write(`${content.length.toString(8).padStart(11, "0")}\0`, 124, "ascii");
  header.write("00000000000\0", 136, "ascii");
  header.write("        ", 148, "ascii");
  header.write("0", 156, "ascii"); // typeflag: regular file
  header.write("ustar\0", 257, "ascii");
  header.write("00", 263, "ascii");

  const paddedSize = Math.ceil(content.length / 512) * 512;
  const contentBlock = Buffer.alloc(paddedSize);
  content.copy(contentBlock);

  const endMarker = Buffer.alloc(1024);
  return zlib.gzipSync(Buffer.concat([header, contentBlock, endMarker]));
}

function buildMinimalZip(fileName: string, content: Buffer, method: number): Buffer {
  const compressed = method === 8 ? zlib.deflateRawSync(content) : content;
  const nameBuf = Buffer.from(fileName, "utf8");

  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(0, 6);
  localHeader.writeUInt16LE(method, 8);
  localHeader.writeUInt16LE(0, 10);
  localHeader.writeUInt16LE(0, 12);
  localHeader.writeUInt32LE(0, 14);
  localHeader.writeUInt32LE(compressed.length, 18);
  localHeader.writeUInt32LE(content.length, 22);
  localHeader.writeUInt16LE(nameBuf.length, 26);
  localHeader.writeUInt16LE(0, 28);
  const localEntry = Buffer.concat([localHeader, nameBuf, compressed]);

  const centralHeader = Buffer.alloc(46);
  centralHeader.writeUInt32LE(0x02014b50, 0);
  centralHeader.writeUInt16LE(20, 4);
  centralHeader.writeUInt16LE(20, 6);
  centralHeader.writeUInt16LE(0, 8);
  centralHeader.writeUInt16LE(method, 10);
  centralHeader.writeUInt16LE(0, 12);
  centralHeader.writeUInt16LE(0, 14);
  centralHeader.writeUInt32LE(0, 16);
  centralHeader.writeUInt32LE(compressed.length, 20);
  centralHeader.writeUInt32LE(content.length, 24);
  centralHeader.writeUInt16LE(nameBuf.length, 28);
  centralHeader.writeUInt16LE(0, 30);
  centralHeader.writeUInt16LE(0, 32);
  centralHeader.writeUInt16LE(0, 34);
  centralHeader.writeUInt16LE(0, 36);
  centralHeader.writeUInt32LE(0, 38);
  centralHeader.writeUInt32LE(0, 42); // local header offset: 0 (local entry comes first)
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

test("extractFileFromTarGz round-trips a regular file", () => {
  const content = Buffer.from("fake gitleaks binary contents");
  const archive = buildMinimalTarGz("gitleaks", content);
  assert.deepEqual(extractFileFromTarGz(archive, "gitleaks"), content);
});

test("extractFileFromTarGz finds a file nested under a directory prefix, by basename", () => {
  const content = Buffer.from("nested binary");
  const archive = buildMinimalTarGz("gitleaks_8.30.1/gitleaks", content);
  assert.deepEqual(extractFileFromTarGz(archive, "gitleaks"), content);
});

test("extractFileFromTarGz throws a clear error when the file isn't present", () => {
  const archive = buildMinimalTarGz("README.md", Buffer.from("not the binary"));
  assert.throws(() => extractFileFromTarGz(archive, "gitleaks"), /not found/);
});

test("extractFileFromZip round-trips a stored (uncompressed) entry", () => {
  const content = Buffer.from("fake gitleaks.exe contents");
  const archive = buildMinimalZip("gitleaks.exe", content, 0);
  assert.deepEqual(extractFileFromZip(archive, "gitleaks.exe"), content);
});

test("extractFileFromZip round-trips a deflated entry", () => {
  const content = Buffer.from("fake gitleaks.exe contents, repeated ".repeat(50));
  const archive = buildMinimalZip("gitleaks.exe", content, 8);
  assert.deepEqual(extractFileFromZip(archive, "gitleaks.exe"), content);
});

test("extractFileFromZip finds a file nested under a directory prefix, by basename", () => {
  const content = Buffer.from("nested exe");
  const archive = buildMinimalZip("gitleaks_8.30.1/gitleaks.exe", content, 0);
  assert.deepEqual(extractFileFromZip(archive, "gitleaks.exe"), content);
});

test("extractFileFromZip throws a clear error when the file isn't present", () => {
  const archive = buildMinimalZip("README.md", Buffer.from("not the binary"), 0);
  assert.throws(() => extractFileFromZip(archive, "gitleaks.exe"), /not found/);
});

test("extractFileFromZip throws on an unsupported compression method", () => {
  // Method 12 is bzip2 — a real value the zip spec defines, that gitleaks' own
  // releases never use and this reader deliberately doesn't implement.
  const archive = buildMinimalZip("gitleaks.exe", Buffer.from("x"), 12);
  assert.throws(() => extractFileFromZip(archive, "gitleaks.exe"), /unsupported/);
});
