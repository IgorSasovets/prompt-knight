import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import { checkRedosSafety } from "../src/redos-check";

const DANGEROUS = ["(a+)+$", "(a*)*", "(.*)+", "(a|a)*"];

for (const source of DANGEROUS) {
  test(`rejects catastrophic pattern: ${source}`, () => {
    const result = checkRedosSafety(source);
    assert.equal(result.safe, false, `expected ${source} to be rejected`);
  });
}

test("rejects an over-long pattern source", () => {
  const result = checkRedosSafety("a".repeat(1000));
  assert.equal(result.safe, false);
});

test("rejects an absurd quantifier bound", () => {
  const result = checkRedosSafety("a{1,5000}");
  assert.equal(result.safe, false);
});

test("rejects a pattern that fails to compile", () => {
  const result = checkRedosSafety("a(");
  assert.equal(result.safe, false);
});

test("accepts bounded nested repetition (e.g. IPv4 octet groups)", () => {
  const result = checkRedosSafety("(?:[0-9]{1,3}\\.){2}[0-9]{1,3}");
  assert.equal(result.safe, true);
});

test("all built-in patterns pass the ReDoS safety check", () => {
  const builtinPath = path.join(__dirname, "..", "..", "patterns", "builtin.json");
  const definitions = JSON.parse(fs.readFileSync(builtinPath, "utf8"));
  for (const def of definitions) {
    const result = checkRedosSafety(def.regex, def.flags ?? "");
    assert.equal(result.safe, true, `built-in pattern "${def.id}" should be safe: ${result.reason}`);
  }
});
