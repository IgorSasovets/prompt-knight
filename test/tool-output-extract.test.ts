import { test } from "node:test";
import assert from "node:assert/strict";
import { extractScannableFields, rebuildToolResponse } from "../src/tool-output-extract";

// These tool_response shapes are not the product of guesswork — they were captured
// from a real Claude Code v2.1.316 session (a PostToolUse hook logging its own
// stdin) during this feature's research, because the hooks reference does not
// publish them (only Write's {filePath, type} shape is documented as an example).
// Keep them as literal fixtures, not approximations.

const FAKE_AWS_KEY = "AKIAEXAMPLEEXAMPLE12";

function readToolResponse(content: string) {
  return {
    type: "text",
    file: {
      filePath: "/private/tmp/sample.txt",
      content,
      numLines: 5,
      startLine: 1,
      totalLines: 5,
    },
  };
}

function grepContentToolResponse(content: string) {
  return {
    mode: "content",
    numFiles: 0,
    filenames: [],
    content,
    numLines: 2,
    totalLines: 2,
  };
}

function bashToolResponse(stdout: string, stderr: string) {
  return { stdout, stderr, interrupted: false, isImage: false, noOutputExpected: false };
}

test("extractScannableFields: Read returns file.content as one field", () => {
  const fields = extractScannableFields("Read", readToolResponse(`AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\n`));
  assert.deepEqual(fields, [{ field: "file.content", text: `AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\n` }]);
});

test("extractScannableFields: Read with empty content yields no fields", () => {
  assert.deepEqual(extractScannableFields("Read", readToolResponse("")), []);
});

test("extractScannableFields: Grep in content mode returns content as one field", () => {
  const fields = extractScannableFields("Grep", grepContentToolResponse(`2:AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}`));
  assert.deepEqual(fields, [{ field: "content", text: `2:AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}` }]);
});

test("extractScannableFields: Grep in files_with_matches/count mode has nothing to scan", () => {
  assert.deepEqual(extractScannableFields("Grep", { mode: "files_with_matches", numFiles: 1, filenames: ["a.txt"] }), []);
  assert.deepEqual(extractScannableFields("Grep", { mode: "count", numFiles: 1 }), []);
});

test("extractScannableFields: Bash returns stdout and stderr as independent fields", () => {
  const fields = extractScannableFields("Bash", bashToolResponse(`AWS_SECRET_ACCESS_KEY=${FAKE_AWS_KEY}`, ""));
  assert.deepEqual(fields, [{ field: "stdout", text: `AWS_SECRET_ACCESS_KEY=${FAKE_AWS_KEY}` }]);
});

test("extractScannableFields: Bash with both stdout and stderr non-empty returns both", () => {
  const fields = extractScannableFields("Bash", bashToolResponse("ok", "warning: something"));
  assert.deepEqual(fields, [
    { field: "stdout", text: "ok" },
    { field: "stderr", text: "warning: something" },
  ]);
});

test("extractScannableFields: unknown tool_name yields no fields", () => {
  assert.deepEqual(extractScannableFields("WebFetch", { body: "secret" }), []);
});

test("rebuildToolResponse: Read keeps sibling keys and only replaces content", () => {
  const original = readToolResponse(`AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\n`);
  const rebuilt = rebuildToolResponse(original, new Map([["file.content", "[REDACTED:aws_keys]\n"]])) as typeof original;
  assert.equal(rebuilt.file.content, "[REDACTED:aws_keys]\n");
  assert.equal(rebuilt.file.filePath, original.file.filePath);
  assert.equal(rebuilt.file.numLines, original.file.numLines);
  assert.equal(rebuilt.file.totalLines, original.file.totalLines);
  assert.equal(rebuilt.type, original.type);
});

test("rebuildToolResponse: Grep keeps sibling keys and only replaces content", () => {
  const original = grepContentToolResponse(`2:AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}`);
  const rebuilt = rebuildToolResponse(original, new Map([["content", "2:[REDACTED:aws_keys]"]])) as typeof original;
  assert.equal(rebuilt.content, "2:[REDACTED:aws_keys]");
  assert.equal(rebuilt.mode, "content");
  assert.deepEqual(rebuilt.filenames, []);
});

test("rebuildToolResponse: Bash replaces stdout and stderr independently", () => {
  const original = bashToolResponse(`AWS_SECRET_ACCESS_KEY=${FAKE_AWS_KEY}`, "a warning");
  const rebuilt = rebuildToolResponse(
    original,
    new Map([["stdout", "[REDACTED:aws_secrets]"]])
  ) as typeof original;
  assert.equal(rebuilt.stdout, "[REDACTED:aws_secrets]");
  assert.equal(rebuilt.stderr, "a warning");
  assert.equal(rebuilt.interrupted, false);
  assert.equal(rebuilt.isImage, false);
});

test("rebuildToolResponse: no replacements returns the original reference untouched", () => {
  const original = readToolResponse("hello");
  assert.equal(rebuildToolResponse(original, new Map()), original);
});
