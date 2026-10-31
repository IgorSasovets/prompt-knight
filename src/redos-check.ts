// Static ReDoS-safety heuristic (D8, TM-1, REQ-T1-07). This is NOT a formal proof of
// linear-time matching — it's a conservative rejection of the well-known catastrophic-
// backtracking shapes (nested unbounded quantifiers, repeated wildcard runs, overlong
// sources). A pattern that passes this check still goes through the runtime timeout
// backstop (see pattern-worker.ts) when it's a custom/user-supplied pattern.

export const MAX_PATTERN_SOURCE_LENGTH = 500;
export const MAX_QUANTIFIER_BOUND = 1000;

export interface RedosCheckResult {
  safe: boolean;
  reason?: string;
}

interface Group {
  start: number;
  end: number; // index of closing ')'
  content: string;
}

/** Removes escaped characters and character-class bodies so that quantifier/paren
 * scanning doesn't trip over "[+*]" or "\(" being mistaken for structural tokens. */
function stripNoise(source: string): string {
  let out = "";
  let inClass = false;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === "\\") {
      out += "\\.";
      i++;
      continue;
    }
    if (c === "[" && !inClass) {
      inClass = true;
      out += "[";
      continue;
    }
    if (c === "]" && inClass) {
      inClass = false;
      out += "]";
      continue;
    }
    if (inClass) {
      out += "x"; // neutralize contents of the class
      continue;
    }
    out += c;
  }
  return out;
}

function findTopLevelAndNestedGroups(source: string): Group[] {
  const groups: Group[] = [];
  const stack: number[] = [];
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (c === "(") {
      stack.push(i);
    } else if (c === ")") {
      const start = stack.pop();
      if (start !== undefined) {
        groups.push({ start, end: i, content: source.slice(start + 1, i) });
      }
    }
  }
  return groups;
}

/** True if `text` contains an unbounded quantifier (+, *, or {n,} with no upper bound)
 * outside of nested sub-groups that are themselves already counted separately. */
function hasUnboundedQuantifier(text: string): boolean {
  if (/[+*]/.test(text.replace(/\\./g, ""))) return true;
  if (/\{\d*,\}/.test(text)) return true;
  return false;
}

function quantifierAfter(source: string, pos: number): string | null {
  const rest = source.slice(pos);
  const m = rest.match(/^(\+|\*|\{\d*,?\d*\})/);
  return m ? m[1] ?? null : null;
}

function isUnboundedToken(token: string): boolean {
  if (token === "+" || token === "*") return true;
  const m = token.match(/^\{(\d*),(\d*)\}$/);
  if (m) return m[2] === ""; // "{n,}" has no upper bound
  return false;
}

function boundedTokenMax(token: string): number | null {
  const m = token.match(/^\{(\d*),?(\d*)\}$/);
  if (!m) return null;
  const upper = m[2] || m[1];
  return upper ? parseInt(upper, 10) : null;
}

export function checkRedosSafety(source: string, _flags?: string): RedosCheckResult {
  if (source.length > MAX_PATTERN_SOURCE_LENGTH) {
    return { safe: false, reason: `pattern source exceeds ${MAX_PATTERN_SOURCE_LENGTH} characters` };
  }

  let compiled: RegExp;
  try {
    compiled = new RegExp(source, _flags ?? "");
    void compiled;
  } catch (err) {
    return { safe: false, reason: `pattern does not compile: ${(err as Error).message}` };
  }

  const stripped = stripNoise(source);

  // Reject any bounded quantifier whose upper bound is absurdly large (cheap DoS via
  // huge unrolled repetition at compile/match time).
  const boundedMatches = stripped.matchAll(/\{(\d*),?(\d*)\}/g);
  for (const m of boundedMatches) {
    const max = boundedTokenMax(m[0]);
    if (max !== null && max > MAX_QUANTIFIER_BOUND) {
      return { safe: false, reason: `quantifier bound exceeds ${MAX_QUANTIFIER_BOUND}: ${m[0]}` };
    }
  }

  // Reject nested unbounded quantifiers: a group quantified unboundedly whose own
  // content already contains an unbounded quantifier, e.g. (a+)+, (a*)*, (.*)+.
  const groups = findTopLevelAndNestedGroups(stripped);
  for (const group of groups) {
    const afterToken = quantifierAfter(stripped, group.end + 1);
    if (!afterToken || !isUnboundedToken(afterToken)) continue;
    if (hasUnboundedQuantifier(group.content)) {
      return {
        safe: false,
        reason: `nested unbounded quantifier detected around position ${group.start}`,
      };
    }
    // Overlapping unbounded alternatives under an unbounded quantifier, e.g. (a|a)*.
    const alternatives = group.content.split("|");
    if (alternatives.length > 1) {
      const seen = new Set<string>();
      for (const alt of alternatives) {
        const trimmed = alt.trim();
        if (seen.has(trimmed)) {
          return {
            safe: false,
            reason: `overlapping alternation under an unbounded quantifier around position ${group.start}`,
          };
        }
        seen.add(trimmed);
      }
    }
  }

  // Reject two consecutive unanchored wildcard runs, e.g. ".*.*" or ".+.+" — not
  // exponential, but a cheap-to-reject performance smell with no legitimate use here.
  if (/\.[*+]\s*\.[*+]/.test(stripped)) {
    return { safe: false, reason: "consecutive wildcard quantifiers detected" };
  }

  return { safe: true };
}
