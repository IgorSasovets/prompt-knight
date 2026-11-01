import { test } from "node:test";
import assert from "node:assert/strict";
import { matchesAnyDenyPattern, matchesGlobSegment } from "../src/glob-match";

test("matchesGlobSegment: exact match", () => {
  assert.equal(matchesGlobSegment("credentials", "credentials"), true);
  assert.equal(matchesGlobSegment("credentials", "other"), false);
});

test("matchesGlobSegment: * matches any run including empty", () => {
  assert.equal(matchesGlobSegment("*.pem", "server.pem"), true);
  assert.equal(matchesGlobSegment("*.pem", ".pem"), true);
  assert.equal(matchesGlobSegment("*.pem", "server.key"), false);
  assert.equal(matchesGlobSegment("id_rsa*", "id_rsa"), true);
  assert.equal(matchesGlobSegment("id_rsa*", "id_rsa.pub"), true);
  assert.equal(matchesGlobSegment("id_rsa*", "id_dsa"), false);
});

test("matchesGlobSegment: ? matches exactly one character", () => {
  assert.equal(matchesGlobSegment(".env.?", ".env.a"), true);
  assert.equal(matchesGlobSegment(".env.?", ".env."), false);
  assert.equal(matchesGlobSegment(".env.?", ".env.ab"), false);
});

test("matchesGlobSegment: multiple stars", () => {
  assert.equal(matchesGlobSegment("*secret*key*", "my-secret-signing-key-v2"), true);
  assert.equal(matchesGlobSegment("*secret*key*", "my-public-cert"), false);
});

test("matchesAnyDenyPattern: single-segment pattern matches basename anywhere", () => {
  assert.equal(matchesAnyDenyPattern("/home/user/project/server.pem", ["*.pem"]), "*.pem");
  assert.equal(matchesAnyDenyPattern("/home/user/project/notes.txt", ["*.pem"]), null);
});

test("matchesAnyDenyPattern: multi-segment pattern matches trailing segments only", () => {
  assert.equal(matchesAnyDenyPattern("/home/user/.ssh/id_rsa", [".ssh/*"]), ".ssh/*");
  assert.equal(matchesAnyDenyPattern("/home/user/project/.ssh/config", [".ssh/*"]), ".ssh/*");
  // "id_rsa" alone, outside a .ssh directory, must not match the 2-segment pattern.
  assert.equal(matchesAnyDenyPattern("/home/user/project/id_rsa", [".ssh/*"]), null);
});

test("matchesAnyDenyPattern: .env and .env.* from the default deny list", () => {
  const patterns = [".env", ".env.*"];
  assert.equal(matchesAnyDenyPattern("/repo/.env", patterns), ".env");
  assert.equal(matchesAnyDenyPattern("/repo/.env.local", patterns), ".env.*");
  assert.equal(matchesAnyDenyPattern("/repo/.env.example", patterns), ".env.*");
  assert.equal(matchesAnyDenyPattern("/repo/config/integrations.js", patterns), null);
});

test("matchesAnyDenyPattern: returns null when nothing matches", () => {
  assert.equal(matchesAnyDenyPattern("/repo/src/index.ts", [".env", "*.pem", ".ssh/*"]), null);
});

test("matchesAnyDenyPattern: first matching pattern wins, order preserved", () => {
  assert.equal(matchesAnyDenyPattern("/repo/.env.local", [".env.*", "*.local"]), ".env.*");
});
