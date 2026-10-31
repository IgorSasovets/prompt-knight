import { test } from "node:test";
import assert from "node:assert/strict";
import * as http from "http";
import { AddressInfo } from "net";
import { callOllama, isLocalHostname, validateOllamaResponse } from "../src/tier2-ollama";
import { Tier2Config } from "../src/types";

function baseTier2Config(overrides: Partial<Tier2Config> = {}): Tier2Config {
  return {
    enabled: true,
    ollamaUrl: "http://127.0.0.1:1", // overridden per-test to the stub server's URL
    allowNonLocal: false,
    model: "llama3.2:3b",
    timeoutMs: 2000,
    confidenceThreshold: 0.7,
    fallbackOnError: "mode-dependent",
    ...overrides,
  };
}

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

/** Starts a throwaway HTTP server on 127.0.0.1 standing in for Ollama's /api/generate,
 * so Tier 2 gets real integration coverage without depending on an actual Ollama
 * install (which, like gitleaks in Phase 2, may not be present in the test
 * environment). Returns the base URL and a stop() to close it. */
async function startStubServer(handler: Handler): Promise<{ url: string; stop: () => Promise<void> }> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    stop: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function ollamaResponseBody(innerResponseJson: unknown): string {
  return JSON.stringify({
    model: "llama3.2:3b",
    created_at: new Date().toISOString(),
    response: JSON.stringify(innerResponseJson),
    done: true,
  });
}

test("isLocalHostname: recognizes localhost, 127.0.0.0/8, and ::1", () => {
  assert.equal(isLocalHostname("http://localhost:11434"), true);
  assert.equal(isLocalHostname("http://127.0.0.1:11434"), true);
  assert.equal(isLocalHostname("http://127.5.9.2:11434"), true);
  assert.equal(isLocalHostname("http://[::1]:11434"), true);
});

test("isLocalHostname: rejects a remote host and the 0.0.0.0 bind-wildcard", () => {
  assert.equal(isLocalHostname("http://ollama.example.com:11434"), false);
  assert.equal(isLocalHostname("http://0.0.0.0:11434"), false);
});

test("isLocalHostname: an unparseable URL is treated as non-local", () => {
  assert.equal(isLocalHostname("not a url"), false);
});

test("validateOllamaResponse: accepts a well-formed response", () => {
  const result = validateOllamaResponse({
    contains_pii: true,
    categories: ["email"],
    confidence: 0.9,
    evidence: ["a@b.com"],
  });
  assert.deepEqual(result, { containsPii: true, categories: ["email"], confidence: 0.9, evidence: ["a@b.com"] });
});

test("validateOllamaResponse: rejects wrong field types", () => {
  assert.equal(validateOllamaResponse({ contains_pii: "yes", categories: [], confidence: 0.9, evidence: [] }), null);
  assert.equal(validateOllamaResponse({ contains_pii: true, categories: "email", confidence: 0.9, evidence: [] }), null);
  assert.equal(validateOllamaResponse({ contains_pii: true, categories: [1, 2], confidence: 0.9, evidence: [] }), null);
  assert.equal(validateOllamaResponse({ contains_pii: true, categories: [], confidence: "high", evidence: [] }), null);
  assert.equal(validateOllamaResponse({ contains_pii: true, categories: [], confidence: 0.9, evidence: [1, 2] }), null);
  assert.equal(validateOllamaResponse({ contains_pii: true, categories: [], confidence: 0.9, evidence: "x" }), null);
});

test("validateOllamaResponse: rejects a confidence outside [0, 1]", () => {
  assert.equal(validateOllamaResponse({ contains_pii: true, categories: [], confidence: 1.5, evidence: [] }), null);
  assert.equal(validateOllamaResponse({ contains_pii: true, categories: [], confidence: -0.1, evidence: [] }), null);
});

test("validateOllamaResponse: rejects a missing required field", () => {
  assert.equal(validateOllamaResponse({ contains_pii: true, confidence: 0.9, evidence: [] }), null);
  assert.equal(validateOllamaResponse({ contains_pii: true, categories: [], confidence: 0.9 }), null);
});

test("validateOllamaResponse: aligns evidence to categories by index, padding/truncating a mismatch", () => {
  const tooShort = validateOllamaResponse({
    contains_pii: true,
    categories: ["email", "phone_number"],
    confidence: 0.9,
    evidence: ["a@b.com"],
  });
  assert.deepEqual(tooShort?.evidence, ["a@b.com", ""]);

  const tooLong = validateOllamaResponse({
    contains_pii: true,
    categories: ["email"],
    confidence: 0.9,
    evidence: ["a@b.com", "extra, ignored"],
  });
  assert.deepEqual(tooLong?.evidence, ["a@b.com"]);
});

test("validateOllamaResponse: truncates an overlong evidence string to 200 characters", () => {
  const long = "x".repeat(500);
  const result = validateOllamaResponse({ contains_pii: true, categories: ["email"], confidence: 0.9, evidence: [long] });
  assert.equal(result?.evidence[0]?.length, 200);
});

test("callOllama: skips without a network call when non-local and allowNonLocal is false", async () => {
  const config = baseTier2Config({ ollamaUrl: "http://example.com:11434", allowNonLocal: false });
  const outcome = await callOllama("some prompt", config, 1_000_000);
  assert.equal(outcome.kind, "skipped");
});

test("callOllama: escalates when the stub reports high-confidence PII", async () => {
  const stub = await startStubServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      ollamaResponseBody({
        contains_pii: true,
        categories: ["email", "phone_number"],
        confidence: 0.95,
        evidence: ["a@b.com", "555-1234"],
      })
    );
  });
  try {
    const config = baseTier2Config({ ollamaUrl: stub.url });
    const outcome = await callOllama("my email is a@b.com", config, 1_000_000);
    assert.equal(outcome.kind, "result");
    if (outcome.kind === "result") {
      assert.equal(outcome.detections.length, 2);
      assert.ok(outcome.detections.every((d) => d.source === "tier2"));
      assert.ok(outcome.detections.every((d) => !d.matchedText.includes("a@b.com")));
      assert.deepEqual(
        outcome.evidence.map((e) => e.text),
        ["a@b.com", "555-1234"]
      );
    }
  } finally {
    await stub.stop();
  }
});

test("callOllama: does not escalate when confidence is below the threshold", async () => {
  const stub = await startStubServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(ollamaResponseBody({ contains_pii: true, categories: ["email"], confidence: 0.3, evidence: ["a@b.com"] }));
  });
  try {
    const config = baseTier2Config({ ollamaUrl: stub.url, confidenceThreshold: 0.7 });
    const outcome = await callOllama("maybe an email", config, 1_000_000);
    assert.equal(outcome.kind, "result");
    if (outcome.kind === "result") assert.deepEqual(outcome.detections, []);
  } finally {
    await stub.stop();
  }
});

test("callOllama: a malformed JSON model response is discarded, not treated as a failure", async () => {
  const stub = await startStubServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ model: "x", response: "not valid json {{{", done: true }));
  });
  try {
    const outcome = await callOllama("text", baseTier2Config({ ollamaUrl: stub.url }), 1_000_000);
    assert.equal(outcome.kind, "result");
    if (outcome.kind === "result") assert.deepEqual(outcome.detections, []);
  } finally {
    await stub.stop();
  }
});

test("callOllama: a non-2xx HTTP response is a failure (REQ-T2-06)", async () => {
  const stub = await startStubServer((_req, res) => {
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("internal error");
  });
  try {
    const outcome = await callOllama("text", baseTier2Config({ ollamaUrl: stub.url }), 1_000_000);
    assert.equal(outcome.kind, "failed");
  } finally {
    await stub.stop();
  }
});

test("callOllama: a timeout is a failure (REQ-T2-06)", async () => {
  const stub = await startStubServer((_req, res) => {
    setTimeout(() => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(ollamaResponseBody({ contains_pii: false, categories: [], confidence: 0, evidence: [] }));
    }, 500);
  });
  try {
    const config = baseTier2Config({ ollamaUrl: stub.url, timeoutMs: 50 });
    const outcome = await callOllama("text", config, 1_000_000);
    assert.equal(outcome.kind, "failed");
  } finally {
    await stub.stop();
  }
});

test("callOllama: connection refused (nothing listening) is a failure (REQ-T2-06)", async () => {
  // Port 1 is a privileged, essentially-never-bound port — fast, reliable ECONNREFUSED.
  const config = baseTier2Config({ ollamaUrl: "http://127.0.0.1:1", timeoutMs: 2000 });
  const outcome = await callOllama("text", config, 1_000_000);
  assert.equal(outcome.kind, "failed");
});

test("callOllama: the system instructions never embed the prompt text (REQ-T2-07)", async () => {
  let capturedBody: string = "";
  const stub = await startStubServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      capturedBody = Buffer.concat(chunks).toString("utf8");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(ollamaResponseBody({ contains_pii: false, categories: [], confidence: 0, evidence: [] }));
    });
  });
  try {
    const secretMarker = "UNIQUE_MARKER_ignore_previous_instructions_12345";
    await callOllama(secretMarker, baseTier2Config({ ollamaUrl: stub.url }), 1_000_000);
    const parsedBody = JSON.parse(capturedBody);
    assert.ok(parsedBody.prompt.includes(secretMarker)); // lives in the data field...
    assert.ok(!parsedBody.system.includes(secretMarker)); // ...never in the system field
  } finally {
    await stub.stop();
  }
});
