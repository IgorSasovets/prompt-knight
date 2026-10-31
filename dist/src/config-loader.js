"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.userConfigDirFor = userConfigDirFor;
exports.isPathWithin = isPathWithin;
exports.resolveSandboxedPath = resolveSandboxedPath;
exports.loadConfig = loadConfig;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const types_1 = require("./types");
const validation_1 = require("./validation");
function userConfigDirFor(homedir) {
    return path.join(homedir, ".prompt-knight");
}
function deepMerge(base, override) {
    if (!(0, validation_1.isPlainObject)(override))
        return base;
    const baseObj = base;
    const result = { ...baseObj };
    for (const [key, value] of Object.entries(override)) {
        const baseValue = baseObj[key];
        if ((0, validation_1.isPlainObject)(baseValue) && (0, validation_1.isPlainObject)(value)) {
            result[key] = deepMerge(baseValue, value);
        }
        else {
            result[key] = value;
        }
    }
    return result;
}
function readJsonFile(filePath) {
    try {
        if (!fs.existsSync(filePath))
            return {};
        const raw = fs.readFileSync(filePath, "utf8");
        return { value: JSON.parse(raw) };
    }
    catch (err) {
        return { error: `Failed to read/parse ${filePath}: ${err.message}` };
    }
}
// Resolves symlinks via fs.realpathSync wherever possible, even when the final path
// segment doesn't exist yet (e.g. a log file not yet created) — falls back to
// resolving the nearest existing ancestor directory and rejoining the remaining
// segments, so two paths that differ only by an unresolved symlink (such as macOS's
// /tmp -> /private/tmp) still compare equal.
function safeRealPath(p) {
    const resolved = path.resolve(p);
    try {
        return fs.realpathSync(resolved);
    }
    catch {
        const parent = path.dirname(resolved);
        if (parent === resolved)
            return resolved;
        return path.join(safeRealPath(parent), path.basename(resolved));
    }
}
/** True if `candidate` resolves to `root` itself or somewhere underneath it. */
function isPathWithin(root, candidate) {
    const resolvedRoot = safeRealPath(root);
    const resolvedCandidate = safeRealPath(candidate);
    if (resolvedRoot === resolvedCandidate)
        return true;
    const rel = path.relative(resolvedRoot, resolvedCandidate);
    return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}
/**
 * Resolves a user-configured path against `baseDir`, refusing (REQ-CFG-02, TM-5) if the
 * result escapes every directory in `allowedRoots`. Returns null + pushes an error onto
 * `errors` on refusal; the caller decides the fallback behavior.
 */
function resolveSandboxedPath(configuredPath, baseDir, allowedRoots, label, errors) {
    const resolved = path.resolve(baseDir, configuredPath);
    const ok = allowedRoots.some((root) => isPathWithin(root, resolved));
    if (!ok) {
        errors.push(`Refusing ${label} outside permitted directories: ${configuredPath}`);
        return null;
    }
    return resolved;
}
function loadConfig(pluginRoot, projectRoot, homedir = os.homedir()) {
    const errors = [];
    const userConfigDir = userConfigDirFor(homedir);
    let config = types_1.SECURE_DEFAULTS;
    let lastValid = types_1.SECURE_DEFAULTS;
    const tiers = [
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
        if (result.value === undefined)
            continue; // file absent is not an error
        config = deepMerge(config, result.value);
        lastValid = config;
    }
    return { config, pluginRoot, userConfigDir, projectRoot, errors };
}
