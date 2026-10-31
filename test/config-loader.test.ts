import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { isPathWithin, loadConfig, resolveSandboxedPath, userConfigDirFor } from "../src/config-loader";

const pluginRoot = path.join(__dirname, "..", "..");

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("loads plugin defaults when no user/project config exists", () => {
  const homedir = mkTmp("promptknight-home-");
  const projectRoot = mkTmp("promptknight-project-");
  const { config, errors } = loadConfig(pluginRoot, projectRoot, homedir);
  assert.equal(config.mode, "block");
  assert.equal(config.tier1.enabled, true);
  assert.equal(config.tier2.enabled, false);
  assert.deepEqual(errors, []);
});

test("project config overrides user config overrides plugin default", () => {
  const homedir = mkTmp("promptknight-home-");
  const projectRoot = mkTmp("promptknight-project-");
  const userDir = userConfigDirFor(homedir);
  fs.mkdirSync(userDir, { recursive: true });
  fs.writeFileSync(path.join(userDir, "config.json"), JSON.stringify({ mode: "warn" }));
  fs.writeFileSync(path.join(projectRoot, ".prompt-knight.json"), JSON.stringify({ mode: "audit" }));

  const { config } = loadConfig(pluginRoot, projectRoot, homedir);
  assert.equal(config.mode, "audit");
});

test("nested keys merge rather than replace the whole sub-object", () => {
  const homedir = mkTmp("promptknight-home-");
  const projectRoot = mkTmp("promptknight-project-");
  fs.writeFileSync(
    path.join(projectRoot, ".prompt-knight.json"),
    JSON.stringify({ tier1: { patterns: { aws_keys: false } } })
  );

  const { config } = loadConfig(pluginRoot, projectRoot, homedir);
  assert.equal(config.tier1.patterns.aws_keys, false);
  assert.equal(config.tier1.patterns.jwt_tokens, true); // untouched sibling survives the merge
});

test("malformed project config falls back to the last valid configuration", () => {
  const homedir = mkTmp("promptknight-home-");
  const projectRoot = mkTmp("promptknight-project-");
  const userDir = userConfigDirFor(homedir);
  fs.mkdirSync(userDir, { recursive: true });
  fs.writeFileSync(path.join(userDir, "config.json"), JSON.stringify({ mode: "warn" }));
  fs.writeFileSync(path.join(projectRoot, ".prompt-knight.json"), "{ not valid json");

  const { config, errors } = loadConfig(pluginRoot, projectRoot, homedir);
  assert.equal(config.mode, "warn"); // last valid tier (user config), not the secure hardcoded default
  assert.ok(errors.some((e) => e.includes("Failed to read/parse")));
});

test("isPathWithin accepts a nested path and rejects a sibling with a similar prefix", () => {
  const root = mkTmp("promptknight-root-");
  const nested = path.join(root, "sub", "file.json");
  fs.mkdirSync(path.dirname(nested), { recursive: true });
  fs.writeFileSync(nested, "{}");
  assert.equal(isPathWithin(root, nested), true);

  const sibling = `${root}-evil`;
  fs.mkdirSync(sibling, { recursive: true });
  assert.equal(isPathWithin(root, sibling), false);
  fs.rmSync(sibling, { recursive: true, force: true });
});

test("resolveSandboxedPath refuses a path that escapes every allowed root", () => {
  const allowed = mkTmp("promptknight-allowed-");
  const outside = mkTmp("promptknight-outside-");
  const errors: string[] = [];
  const result = resolveSandboxedPath(path.join(outside, "x.json"), allowed, [allowed], "test.path", errors);
  assert.equal(result, null);
  assert.ok(errors.length === 1);
});

test("resolveSandboxedPath accepts a path traversal that still lands back inside the root", () => {
  const allowed = mkTmp("promptknight-allowed-");
  fs.mkdirSync(path.join(allowed, "sub"), { recursive: true });
  const errors: string[] = [];
  const result = resolveSandboxedPath("sub/../ok.json", allowed, [allowed], "test.path", errors);
  assert.equal(result, path.join(allowed, "ok.json"));
  assert.deepEqual(errors, []);
});
