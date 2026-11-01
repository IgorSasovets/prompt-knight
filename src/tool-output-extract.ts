// Per-tool adapter between a PostToolUse `tool_response` payload and scannable text,
// and back (REQ-TOOL-05, REQ-TOOL-07, D22). Shapes below were captured empirically
// against a real Claude Code session (v2.1.316) — the hooks reference does not
// publish `tool_response`'s exact schema per tool, only "depends on the tool" — so
// treat every field access here as verified-not-assumed, and re-verify against a
// debug-logged payload before changing it (AGENTS.md's "research before
// implementing" rule).
//
// Read:  {type:"text", file:{filePath, content, numLines, startLine, totalLines}}
// Grep:  {mode:"content", numFiles, filenames, content, numLines, totalLines}
//        (other modes — "files_with_matches", "count" — carry no raw text)
// Bash:  {stdout, stderr, interrupted, isImage, noOutputExpected}
//
// Bash's stdout/stderr are kept as two independent fields rather than joined into one
// string: a join would make the reverse split ambiguous whenever stdout itself
// contains a newline, which is the common case.
import { isPlainObject } from "./validation";

export type ScanField = "file.content" | "content" | "stdout" | "stderr";

export interface ExtractedField {
  field: ScanField;
  text: string;
}

export function extractScannableFields(toolName: string, toolResponse: unknown): ExtractedField[] {
  if (!isPlainObject(toolResponse)) return [];

  if (toolName === "Read") {
    const file = toolResponse.file;
    if (isPlainObject(file) && typeof file.content === "string" && file.content.length > 0) {
      return [{ field: "file.content", text: file.content }];
    }
    return [];
  }

  if (toolName === "Grep") {
    if (toolResponse.mode === "content" && typeof toolResponse.content === "string" && toolResponse.content.length > 0) {
      return [{ field: "content", text: toolResponse.content }];
    }
    return [];
  }

  if (toolName === "Bash") {
    const fields: ExtractedField[] = [];
    if (typeof toolResponse.stdout === "string" && toolResponse.stdout.length > 0) {
      fields.push({ field: "stdout", text: toolResponse.stdout });
    }
    if (typeof toolResponse.stderr === "string" && toolResponse.stderr.length > 0) {
      fields.push({ field: "stderr", text: toolResponse.stderr });
    }
    return fields;
  }

  return [];
}

/**
 * Clones `toolResponse` and overwrites only the fields present in `replacements`,
 * leaving every sibling key (`numLines`, `totalLines`, `filenames`, `interrupted`,
 * `isImage`, etc.) untouched — this exact-shape fidelity is what Claude Code's
 * `updatedToolOutput` requires; anything else is silently discarded and the original,
 * unredacted output reaches the model instead (D22).
 */
export function rebuildToolResponse(toolResponse: unknown, replacements: Map<ScanField, string>): unknown {
  if (!isPlainObject(toolResponse) || replacements.size === 0) return toolResponse;
  const result: Record<string, unknown> = { ...toolResponse };

  const fileReplacement = replacements.get("file.content");
  if (fileReplacement !== undefined && isPlainObject(toolResponse.file)) {
    result.file = { ...toolResponse.file, content: fileReplacement };
  }

  const contentReplacement = replacements.get("content");
  if (contentReplacement !== undefined) result.content = contentReplacement;

  const stdoutReplacement = replacements.get("stdout");
  if (stdoutReplacement !== undefined) result.stdout = stdoutReplacement;

  const stderrReplacement = replacements.get("stderr");
  if (stderrReplacement !== undefined) result.stderr = stderrReplacement;

  return result;
}
