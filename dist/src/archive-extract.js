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
exports.extractFileFromTarGz = extractFileFromTarGz;
exports.extractFileFromZip = extractFileFromZip;
const zlib = __importStar(require("zlib"));
// Minimal, narrowly-scoped tar.gz/zip readers: enough to find one named file inside
// a small release archive and return its bytes, not general-purpose archive
// libraries. Written by hand (zero runtime deps, D4) rather than pulling in
// `tar`/`adm-zip`/`unzipper` for a setup-time convenience tool.
function readStringField(block, offset, length) {
    return block.subarray(offset, offset + length).toString("ascii").replace(/\0.*$/, "");
}
function readOctalField(block, offset, length) {
    const raw = readStringField(block, offset, length).trim();
    return raw ? parseInt(raw, 8) : 0;
}
/**
 * Extracts one named file from a gzip-compressed USTAR tar archive (the format
 * gitleaks ships its macOS/Linux releases in). Only understands plain regular-file
 * entries with short names — no GNU long-name or PAX extended-header support, which
 * gitleaks' flat release archives don't use.
 */
function extractFileFromTarGz(gzBuffer, fileName) {
    const tarBuffer = zlib.gunzipSync(gzBuffer);
    let offset = 0;
    while (offset + 512 <= tarBuffer.length) {
        const header = tarBuffer.subarray(offset, offset + 512);
        if (header.every((b) => b === 0))
            break; // end-of-archive marker
        const name = readStringField(header, 0, 100);
        const prefix = readStringField(header, 345, 155);
        const fullName = prefix ? `${prefix}/${name}` : name;
        const size = readOctalField(header, 124, 12);
        const typeflag = String.fromCharCode(header[156] ?? 0);
        const contentStart = offset + 512;
        const paddedSize = Math.ceil(size / 512) * 512;
        const baseName = fullName.split("/").pop() ?? fullName;
        if ((typeflag === "0" || typeflag === "\0") && (fullName === fileName || baseName === fileName)) {
            return Buffer.from(tarBuffer.subarray(contentStart, contentStart + size));
        }
        offset = contentStart + paddedSize;
    }
    throw new Error(`"${fileName}" not found in tar archive`);
}
const ZIP_EOCD_SIGNATURE = 0x06054b50;
const ZIP_CENTRAL_DIR_SIGNATURE = 0x02014b50;
const ZIP_LOCAL_HEADER_SIGNATURE = 0x04034b50;
const ZIP_MAX_COMMENT_LENGTH = 65535;
function findEndOfCentralDirectory(buffer) {
    const searchStart = Math.max(0, buffer.length - 22 - ZIP_MAX_COMMENT_LENGTH);
    for (let i = buffer.length - 22; i >= searchStart; i--) {
        if (buffer.readUInt32LE(i) === ZIP_EOCD_SIGNATURE)
            return i;
    }
    throw new Error("not a valid zip archive (end-of-central-directory record not found)");
}
function readZipEntryData(buffer, localHeaderOffset, compressionMethod, compressedSize) {
    if (buffer.readUInt32LE(localHeaderOffset) !== ZIP_LOCAL_HEADER_SIGNATURE) {
        throw new Error("malformed zip local file header");
    }
    const filenameLength = buffer.readUInt16LE(localHeaderOffset + 26);
    const extraLength = buffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + filenameLength + extraLength;
    const compressed = buffer.subarray(dataStart, dataStart + compressedSize);
    if (compressionMethod === 0)
        return Buffer.from(compressed);
    if (compressionMethod === 8)
        return zlib.inflateRawSync(compressed);
    throw new Error(`unsupported zip compression method: ${compressionMethod}`);
}
/**
 * Extracts one named file from a zip archive (the format gitleaks ships its
 * Windows releases in). Supports the two compression methods gitleaks' own
 * releases actually use: stored (0) and deflate (8).
 */
function extractFileFromZip(zipBuffer, fileName) {
    const eocdOffset = findEndOfCentralDirectory(zipBuffer);
    const totalEntries = zipBuffer.readUInt16LE(eocdOffset + 10);
    const centralDirOffset = zipBuffer.readUInt32LE(eocdOffset + 16);
    let offset = centralDirOffset;
    for (let i = 0; i < totalEntries; i++) {
        if (zipBuffer.readUInt32LE(offset) !== ZIP_CENTRAL_DIR_SIGNATURE) {
            throw new Error("malformed zip central directory entry");
        }
        const compressionMethod = zipBuffer.readUInt16LE(offset + 10);
        const compressedSize = zipBuffer.readUInt32LE(offset + 20);
        const filenameLength = zipBuffer.readUInt16LE(offset + 28);
        const extraLength = zipBuffer.readUInt16LE(offset + 30);
        const commentLength = zipBuffer.readUInt16LE(offset + 32);
        const localHeaderOffset = zipBuffer.readUInt32LE(offset + 42);
        const entryName = zipBuffer.subarray(offset + 46, offset + 46 + filenameLength).toString("utf8");
        const baseName = entryName.split("/").pop() ?? entryName;
        if (entryName === fileName || baseName === fileName) {
            return readZipEntryData(zipBuffer, localHeaderOffset, compressionMethod, compressedSize);
        }
        offset += 46 + filenameLength + extraLength + commentLength;
    }
    throw new Error(`"${fileName}" not found in zip archive`);
}
