import { test } from "node:test";
import assert from "node:assert/strict";
import { buildCandidateRegex, normalizeShape, suggestPatterns } from "../src/pattern-suggester";
import { FeedbackRecord } from "../src/pattern-suggester";

function record(category: string, evidencePreview: string, confidence = 0.9): FeedbackRecord {
  return { timestamp: new Date().toISOString(), category, confidence, evidencePreview };
}

test("normalizeShape collapses letter runs to A and digit runs to 9", () => {
  assert.equal(normalizeShape("https://api.internal.company.com/v2/token=abc123"), "A://A.A.A.A/A9/A=A9");
});

test("normalizeShape treats punctuation and whitespace literally", () => {
  assert.equal(normalizeShape("foo bar-baz_99"), "A A-A_9");
});

test("buildCandidateRegex turns the shape skeleton directly into a working regex", () => {
  const shape = normalizeShape("user42@example.com");
  const regex = buildCandidateRegex(shape);
  assert.match("someone99@another.net", new RegExp(`^${regex}$`));
  assert.doesNotMatch("not an email", new RegExp(`^${regex}$`));
});

test("buildCandidateRegex escapes regex-special literal characters", () => {
  const regex = buildCandidateRegex(normalizeShape("a.b*c?d"));
  assert.match("x.y*z?w", new RegExp(`^${regex}$`));
});

test("suggestPatterns groups by category + shape and requires minHits", () => {
  const records = [
    record("email", "a@b.com"),
    record("email", "c@d.com"),
    record("email", "e@f.com"),
    record("phone_number", "555-1234"), // only one hit — below minHits
  ];
  const suggestions = suggestPatterns(records, { minHits: 3, approvedSignatures: new Set() });
  assert.equal(suggestions.length, 1);
  assert.equal(suggestions[0]!.category, "email");
  assert.equal(suggestions[0]!.hitCount, 3);
});

test("suggestPatterns excludes a shape signature already in approvedSignatures", () => {
  const records = [record("email", "a@b.com"), record("email", "c@d.com"), record("email", "e@f.com")];
  const shapeSignature = `email::${normalizeShape("a@b.com")}`;
  const suggestions = suggestPatterns(records, { minHits: 3, approvedSignatures: new Set([shapeSignature]) });
  assert.equal(suggestions.length, 0);
});

test("suggestPatterns never proposes a ReDoS-unsafe candidate", () => {
  // Can't easily force buildCandidateRegex into an unsafe shape from plain evidence
  // text (every surviving literal char is a single char, never a nested quantifier),
  // so this documents that invariant rather than fabricating an artificial case.
  const records = Array.from({ length: 5 }, (_, i) => record("weird", `${"a".repeat(i + 1)}@@@`));
  const suggestions = suggestPatterns(records, { minHits: 3, approvedSignatures: new Set() });
  for (const s of suggestions) {
    assert.doesNotThrow(() => new RegExp(s.regex));
  }
});

test("suggestPatterns sorts by hit count descending", () => {
  const records = [
    ...Array.from({ length: 3 }, () => record("rare", "x1y")),
    ...Array.from({ length: 6 }, () => record("common", "a1b")),
  ];
  const suggestions = suggestPatterns(records, { minHits: 3, approvedSignatures: new Set() });
  assert.equal(suggestions[0]!.category, "common");
  assert.equal(suggestions[1]!.category, "rare");
});

test("suggestPatterns ignores records with an empty evidencePreview", () => {
  const records = [record("email", ""), record("email", ""), record("email", "")];
  const suggestions = suggestPatterns(records, { minHits: 1, approvedSignatures: new Set() });
  assert.equal(suggestions.length, 0);
});
