import { test } from "node:test";
import assert from "node:assert/strict";
import { decide } from "../src/enforcement";
import { Detection, Mode } from "../src/types";

const noDetections: Detection[] = [];
const oneDetection: Detection[] = [
  { category: "aws_keys", source: "tier1", patternId: "aws_keys", index: 0, length: 20, matchedText: "AKIAEXAMPLEEXAMPLE12" },
];

const modes: Mode[] = ["block", "warn", "audit"];

for (const mode of modes) {
  test(`${mode} mode: no detections, no error -> allow`, () => {
    assert.equal(decide(mode, noDetections, false), "allow");
  });
}

test("block mode with a detection -> block", () => {
  assert.equal(decide("block", oneDetection, false), "block");
});

test("warn mode with a detection -> warn", () => {
  assert.equal(decide("warn", oneDetection, false), "warn");
});

test("audit mode with a detection -> allow (records only, never interrupts)", () => {
  assert.equal(decide("audit", oneDetection, false), "allow");
});

test("internal error in block mode -> fail closed (block)", () => {
  assert.equal(decide("block", noDetections, true), "block");
  assert.equal(decide("block", oneDetection, true), "block");
});

test("internal error in warn mode -> fail open + warn", () => {
  assert.equal(decide("warn", noDetections, true), "warn");
});

test("internal error in audit mode -> fail open + warn (unlike normal audit-mode detections)", () => {
  assert.equal(decide("audit", noDetections, true), "warn");
});
