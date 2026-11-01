import { test } from "node:test";
import assert from "node:assert/strict";
import { redactByOffsets } from "../src/validation";
import { Detection } from "../src/types";

function detection(overrides: Partial<Detection> = {}): Detection {
  return {
    category: "aws_keys",
    source: "tier1",
    patternId: "aws_keys",
    index: 0,
    length: 0,
    matchedText: "",
    ...overrides,
  };
}

test("redactByOffsets: splices a single verified detection", () => {
  const text = "key: AKIAEXAMPLEEXAMPLE12 end";
  const d = detection({ index: 5, length: 20, matchedText: "AKIAEXAMPLEEXAMPLE12" });
  const result = redactByOffsets(text, [d], (c) => `[REDACTED:${c}]`);
  assert.equal(result.fullyVerifiable, true);
  assert.equal(result.text, "key: [REDACTED:aws_keys] end");
});

test("redactByOffsets: splices multiple non-overlapping detections regardless of order", () => {
  const text = "a=AAAA b=BBBB";
  const d1 = detection({ category: "cat1", index: 2, length: 4, matchedText: "AAAA" });
  const d2 = detection({ category: "cat2", index: 9, length: 4, matchedText: "BBBB" });
  const result = redactByOffsets(text, [d2, d1], (c) => `[${c}]`);
  assert.equal(result.fullyVerifiable, true);
  assert.equal(result.text, "a=[cat1] b=[cat2]");
});

test("redactByOffsets: a Tier2-style synthetic detection (index:0,length:0) fails verification", () => {
  const text = "my coworker's personal email is on file somewhere in here";
  const synthetic = detection({ category: "email", index: 0, length: 0, matchedText: "[semantic-detection:email]" });
  const result = redactByOffsets(text, [synthetic], (c) => `[REDACTED:${c}]`);
  assert.equal(result.fullyVerifiable, false);
  assert.equal(result.text, text);
});

test("redactByOffsets: one bad offset in a batch discards the whole splice", () => {
  const text = "key: AKIAEXAMPLEEXAMPLE12 end";
  const good = detection({ index: 5, length: 20, matchedText: "AKIAEXAMPLEEXAMPLE12" });
  const bad = detection({ category: "email", index: 0, length: 0, matchedText: "[semantic-detection:email]" });
  const result = redactByOffsets(text, [good, bad], (c) => `[REDACTED:${c}]`);
  assert.equal(result.fullyVerifiable, false);
  assert.equal(result.text, text);
});

test("redactByOffsets: an empty detection list is not fully verifiable (nothing to splice)", () => {
  const result = redactByOffsets("hello", [], (c) => `[${c}]`);
  assert.equal(result.fullyVerifiable, false);
  assert.equal(result.text, "hello");
});
