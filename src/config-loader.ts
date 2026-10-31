import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Config, SECURE_DEFAULTS } from "./types";
import { isPlainObject } from "./validation";

export interface ConfigLoadResult {
  config: Config;
  pluginRoot: string;
  userConfigDir: string;
  projectRoot: string;
  errors: string[];
}

export function userConfigDirFor(homedir: string): string {
  return path.join(homedir, ".prompt-knight");
}

function deepMerge<T>(base: T, override: unknown): T {
  if (!isPlainObject(override)) return base;
  const baseObj = base as unknown as Record<string, unknown>;
  const result: Record<string, unknown> = { ...baseObj };
  for (const [key, value] of Object.entries(override)) {
    const baseValue = baseObj[key];
    if (isPlainObject(baseValue) && isPlainObject(value)) {
      result[key] = deepMerge(baseValue, value);
    } else {
      result[key] = value;
    }
  }
  return result as unknown as T;
}

function readJsonFile(filePath: string): { value?: unknown; error?: string } {
  try {
    if (!fs.existsSync(filePath)) return {};
    const raw = fs.readFileSync(filePath, "utf8");
    return { value: JSON.parse(raw) };
  } catch (err) {
    return { error: `Failed to read/parse ${filePath}: ${(err as Error).message}` };
  }
}

// Resolves symlinks via fs.realpathSync wherever possible, even when the final path
// segment doesn't exist yet (e.g. a log file not yet created) — falls back to
// resolving the nearest existing ancestor directory and rejoining the remaining
// segments, so two paths that differ only by an unresolved symlink (such as macOS's
// /tmp -> /private/tmp) still compare equal.
function safeRealPath(p: string): string {
  const resolved = path.resolve(p);
  try {
    return fs.realpathSync(resolved);
  } catch {
    const parent = path.dirname(resolved);
    if (parent === resolved) return resolved;
    return path.join(safeRealPath(parent), path.basename(resolved));
  }
}

/** True if `candidate` resolves to `root` itself or somewhere underneath it. */
export function isPathWithin(root: string, candidate: string): boolean {
  const resolvedRoot = safeRealPath(root);
  const resolvedCandidate = safeRealPath(candidate);
  if (resolvedRoot === resolvedCandidate) return true;
  const rel = path.relative(resolvedRoot, resolvedCandidate);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

/**
 * Resolves a user-configured path against `baseDir`, refusing (REQ-CFG-02, TM-5) if the
 * result escapes every directory in `allowedRoots`. Returns null + pushes an error onto
 * `errors` on refusal; the caller decides the fallback behavior.
 */
export function resolveSandboxedPath(
  configuredPath: string,
  baseDir: string,
  allowedRoots: string[],
  label: string,
  errors: string[]
): string | null {
  const resolved = path.resolve(baseDir, configuredPath);
  const ok = allowedRoots.some((root) => isPathWithin(root, resolved));
  if (!ok) {
    errors.push(`Refusing ${label} outside permitted directories: ${configuredPath}`);
    return null;
  }
  return resolved;
}

export function loadConfig(pluginRoot: string, projectRoot: string, homedir: string = os.homedir()): ConfigLoadResult {
  const errors: string[] = [];
  const userConfigDir = userConfigDirFor(homedir);

  let config: Config = SECURE_DEFAULTS;
  let lastValid: Config = SECURE_DEFAULTS;

  const tiers: Array<{ filePath: string; label: string }> = [
    { filePath: path.join(pluginRoot, "config", "default.json"), label: "plugin default config" },
    { filePath: path.join(userConfigDir, "config.json"), label: "user config" },
    { filePath: path.join(projectRoot, ".prompt-knight.json"), label: "project config" },
  ];

  for (const tier of tiers) {
    const result = readJsonFile(tier.filePath);
    if (result.error) {
      errors.push(`${result.error} — falling back to last valid configuration (${tier.label} ignored).`);
      config = lastValid;
      continue;
    }
    if (result.value === undefined) continue; // file absent is not an error
    config = deepMerge(config, result.value);
    lastValid = config;
  }

  return { config, pluginRoot, userConfigDir, projectRoot, errors };
}
