// Hand-rolled glob matcher for `toolOutput.denyPathPatterns` (D21, REQ-TOOL-03).
// Deliberately not a regex: every other user-configurable pattern in this project
// (custom Tier 1 patterns, self-improvement suggestions) must pass checkRedosSafety()
// before it's ever compiled, because a regex engine's backtracking can blow up on
// crafted input. This matcher sidesteps that review surface entirely by construction
// — the classic two-pointer wildcard algorithm below is bounded by O(pattern·segment)
// with no exponential blowup, so there is nothing for a ReDoS check to catch.

/**
 * Matches a single path segment (no `/` or `\`) against a glob segment supporting
 * `*` (any run of characters, including none) and `?` (exactly one character).
 */
export function matchesGlobSegment(pattern: string, segment: string): boolean {
  let pIdx = 0;
  let sIdx = 0;
  let starPatternIdx = -1;
  let starSegmentIdx = 0;

  while (sIdx < segment.length) {
    const pChar = pIdx < pattern.length ? pattern.charAt(pIdx) : "";
    if (pIdx < pattern.length && (pChar === "?" || pChar === segment.charAt(sIdx))) {
      pIdx += 1;
      sIdx += 1;
    } else if (pIdx < pattern.length && pChar === "*") {
      starPatternIdx = pIdx;
      starSegmentIdx = sIdx;
      pIdx += 1;
    } else if (starPatternIdx !== -1) {
      // Backtrack to the last `*` and let it absorb one more character. Bounded by
      // `segment.length` retries total, not exponential.
      pIdx = starPatternIdx + 1;
      starSegmentIdx += 1;
      sIdx = starSegmentIdx;
    } else {
      return false;
    }
  }

  while (pIdx < pattern.length && pattern.charAt(pIdx) === "*") pIdx += 1;
  return pIdx === pattern.length;
}

function normalizeSegments(p: string): string[] {
  return p.split(/[\\/]+/).filter((s) => s.length > 0);
}

/**
 * Returns the first deny pattern that matches `candidatePath`, or null. A pattern
 * with no `/` matches the path's basename only; a pattern with `/` matches that many
 * trailing path segments (e.g. `.ssh/*` matches `.../.ssh/id_rsa` but not a bare
 * `id_rsa` elsewhere). There is no `**` support — intentionally out of scope for the
 * default deny list, which only needs 1–2 segment patterns.
 */
export function matchesAnyDenyPattern(candidatePath: string, patterns: string[]): string | null {
  const pathSegments = normalizeSegments(candidatePath);
  if (pathSegments.length === 0) return null;

  for (const pattern of patterns) {
    const patternSegments = normalizeSegments(pattern);
    if (patternSegments.length === 0) continue;

    if (patternSegments.length === 1) {
      const basename = pathSegments[pathSegments.length - 1];
      const segment = patternSegments[0];
      if (basename !== undefined && segment !== undefined && matchesGlobSegment(segment, basename)) {
        return pattern;
      }
      continue;
    }

    if (patternSegments.length > pathSegments.length) continue;
    const offset = pathSegments.length - patternSegments.length;
    let allMatch = true;
    for (let i = 0; i < patternSegments.length; i += 1) {
      const patternSegment = patternSegments[i];
      const pathSegment = pathSegments[offset + i];
      if (patternSegment === undefined || pathSegment === undefined || !matchesGlobSegment(patternSegment, pathSegment)) {
        allMatch = false;
        break;
      }
    }
    if (allMatch) return pattern;
  }

  return null;
}
