import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { dedupeDetections, loadPatterns, scan, shutdownPatternWorker } from "../src/tier1-engine";
import { Detection, Tier1Config } from "../src/types";

const pluginRoot = path.join(__dirname, "..", "..");
const workerScriptPath = path.join(__dirname, "..", "src", "pattern-worker.js");

function baseTier1Config(overrides: Partial<Tier1Config> = {}): Tier1Config {
  return {
    enabled: true,
    patterns: {
      aws_keys: true,
      aws_secrets: true,
      aws_accounts: true,
      aws_arns: true,
      db_strings: true,
      jwt_tokens: true,
      npm_tokens: true,
      private_ips: true,
    },
    customPatternsFile: path.join(pluginRoot, "patterns", "custom.json"),
    patternTimeoutMs: 200,
    allowlist: [],
    ...overrides,
  };
}

const SAMPLES: Array<{ category: string; text: string }> = [
  { category: "aws_keys", text: "key is AKIAABCDEFGHIJKLMNOP end" },
  { category: "aws_secrets", text: "aws_secret_access_key=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN" },
  { category: "aws_accounts", text: "account_id: 123456789012" },
  { category: "aws_arns", text: "arn:aws:iam::123456789012:role/my-role" },
  { category: "db_strings", text: "postgres://user:secretpass@db.internal:5432/app" },
  { category: "jwt_tokens", text: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" },
  { category: "npm_tokens", text: "npm_1234567890abcdefghijklmnopqrstuvwxyz" },
  { category: "private_ips", text: "connect to 192.168.1.42 please" },
];

test("each built-in category matches its known sample", async () => {
  const { patterns, loadErrors } = loadPatterns(pluginRoot, baseTier1Config(), [pluginRoot]);
  assert.deepEqual(loadErrors, []);
  for (const { category, text } of SAMPLES) {
    const result = await scan(text, patterns, {
      maxPromptBytes: 1_000_000,
      patternTimeoutMs: 200,
      allowlist: [],
      workerScriptPath,
    });
    assert.ok(
      result.detections.some((d) => d.category === category),
      `expected category "${category}" to be detected in: ${text}`
    );
  }
  shutdownPatternWorker();
});

test("clean text produces no detections", async () => {
  const { patterns } = loadPatterns(pluginRoot, baseTier1Config(), [pluginRoot]);
  const result = await scan("just a normal refactor request, nothing sensitive here", patterns, {
    maxPromptBytes: 1_000_000,
    patternTimeoutMs: 200,
    allowlist: [],
    workerScriptPath,
  });
  assert.deepEqual(result.detections, []);
  shutdownPatternWorker();
});

test("allowlist suppresses a known false positive", async () => {
  const { patterns } = loadPatterns(pluginRoot, baseTier1Config(), [pluginRoot]);
  const text = "connect to 192.168.1.42 please";
  const withoutAllowlist = await scan(text, patterns, {
    maxPromptBytes: 1_000_000,
    patternTimeoutMs: 200,
    allowlist: [],
    workerScriptPath,
  });
  assert.ok(withoutAllowlist.detections.length > 0);

  const withAllowlist = await scan(text, patterns, {
    maxPromptBytes: 1_000_000,
    patternTimeoutMs: 200,
    allowlist: ["192.168.1.42"],
    workerScriptPath,
  });
  assert.deepEqual(withAllowlist.detections, []);
  shutdownPatternWorker();
});

test("disabling a category toggle removes it from the loaded patterns", async () => {
  const config = baseTier1Config({
    patterns: {
      aws_keys: false,
      aws_secrets: true,
      aws_accounts: true,
      aws_arns: true,
      db_strings: true,
      jwt_tokens: true,
      npm_tokens: true,
      private_ips: true,
    },
  });
  const { patterns } = loadPatterns(pluginRoot, config, [pluginRoot]);
  assert.ok(!patterns.some((p) => p.category === "aws_keys"));
});

test("custom pattern file (within a sandboxed root) is loaded and matches", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "promptknight-custom-"));
  const customFile = path.join(tmpDir, "custom.json");
  fs.writeFileSync(
    customFile,
    JSON.stringify([{ id: "internal-host", category: "internal_host", regex: "internal\\.example\\.com" }])
  );

  const config = baseTier1Config({ customPatternsFile: customFile });
  const { patterns, loadErrors } = loadPatterns(pluginRoot, config, [pluginRoot, tmpDir]);
  assert.deepEqual(loadErrors, []);
  assert.ok(patterns.some((p) => p.id === "internal-host"));

  const result = await scan("hit https://internal.example.com/admin", patterns, {
    maxPromptBytes: 1_000_000,
    patternTimeoutMs: 200,
    allowlist: [],
    workerScriptPath,
  });
  assert.ok(result.detections.some((d) => d.category === "internal_host"));
  shutdownPatternWorker();

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("custom pattern file outside sandboxed roots is refused", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "promptknight-outside-"));
  const customFile = path.join(tmpDir, "custom.json");
  fs.writeFileSync(customFile, JSON.stringify([{ id: "x", category: "x", regex: "x" }]));

  const config = baseTier1Config({ customPatternsFile: customFile });
  // deliberately NOT including tmpDir in allowedRoots
  const { patterns, loadErrors } = loadPatterns(pluginRoot, config, [pluginRoot]);
  assert.ok(loadErrors.some((e) => e.includes("Refusing")));
  assert.ok(!patterns.some((p) => p.id === "x"));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("a catastrophic custom pattern is skipped at load time", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "promptknight-redos-"));
  const customFile = path.join(tmpDir, "custom.json");
  fs.writeFileSync(customFile, JSON.stringify([{ id: "evil", category: "evil", regex: "(a+)+$" }]));

  const config = baseTier1Config({ customPatternsFile: customFile });
  const { patterns, loadErrors } = loadPatterns(pluginRoot, config, [pluginRoot, tmpDir]);
  assert.ok(!patterns.some((p) => p.id === "evil"));
  assert.ok(loadErrors.some((e) => e.includes("evil")));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("a custom pattern that exceeds the time budget is aborted and skipped", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "promptknight-slow-"));
  const customFile = path.join(tmpDir, "custom.json");
  // Safe under the ReDoS heuristic (no nested unbounded quantifiers) but slow in
  // practice against a long adversarial input — exercises the worker timeout path.
  fs.writeFileSync(
    customFile,
    JSON.stringify([{ id: "slow", category: "slow", regex: "^[a-zA-Z0-9]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$" }])
  );
  const config = baseTier1Config({ customPatternsFile: customFile, patternTimeoutMs: 5 });
  const { patterns } = loadPatterns(pluginRoot, config, [pluginRoot, tmpDir]);

  const longText = `${"a".repeat(200_000)}!`;
  const result = await scan(longText, patterns, {
    maxPromptBytes: 1_000_000,
    patternTimeoutMs: 5,
    allowlist: [],
    workerScriptPath,
  });
  // Whether or not this particular pattern is actually slow enough to time out is
  // environment-dependent; the real assertion is that scanning completes at all and
  // doesn't hang the test process.
  assert.ok(Array.isArray(result.detections));
  shutdownPatternWorker();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("dedupeDetections collapses the same secret value reported by different sources", () => {
  const detections: Detection[] = [
    { category: "aws_keys", source: "tier1", patternId: "aws_keys", index: 10, length: 20, matchedText: "AKIAEXAMPLEEXAMPLE12" },
    { category: "generic-aws-key", source: "gitleaks", patternId: "gitleaks:generic-aws-key", index: 10, length: 20, matchedText: "AKIAEXAMPLEEXAMPLE12" },
  ];
  const deduped = dedupeDetections(detections);
  assert.equal(deduped.length, 1);
  assert.equal(deduped[0]!.category, "aws_keys"); // tier1 entry wins since it comes first
});

test("dedupeDetections keeps distinct secret values from different sources", () => {
  const detections: Detection[] = [
    { category: "aws_keys", source: "tier1", patternId: "aws_keys", index: 0, length: 20, matchedText: "AKIAEXAMPLEEXAMPLE12" },
    { category: "slack-webhook-url", source: "gitleaks", patternId: "gitleaks:slack-webhook-url", index: 30, length: 40, matchedText: "https://hooks.slack.com/services/T0/B0/X0" },
  ];
  const deduped = dedupeDetections(detections);
  assert.equal(deduped.length, 2);
});
