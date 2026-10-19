/**
 * Span algebra and redaction.
 *
 * Detectors are independent and they overlap: an AWS secret assigned in an env
 * line trips both `env-secret` and `high-entropy`, and a JWT sitting in a URL
 * trips `url-with-token` and `jwt`. Overlapping spans have to collapse into one
 * before anything is replaced, otherwise the offsets shift underneath you and
 * you redact half a string.
 */

/** @typedef {import('./detectors.js').Span} Span */

const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Sort by start, then prefer the longer span, then the more severe one.
 * @param {Span[]} spans
 */
export function sortSpans(spans) {
  return [...spans].sort(
    (a, b) =>
      a.start - b.start ||
      b.end - b.start - (a.end - a.start) ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
  );
}

/**
 * Collapse overlapping or touching spans into a single span that covers the union.
 * The merged span keeps the most severe severity and the widest category label.
 *
 * @param {Span[]} spans
 * @returns {Span[]}
 */
export function mergeSpans(spans) {
  const sorted = sortSpans(spans);
  /** @type {Span[]} */
  const merged = [];

  for (const span of sorted) {
    if (span.end <= span.start) continue;
    const last = merged[merged.length - 1];

    if (!last || span.start >= last.end) {
      merged.push({ ...span });
      continue;
    }

    // Overlap. Absorb.
    const moreSevere =
      SEVERITY_RANK[span.severity] > SEVERITY_RANK[last.severity] ? span : last;
    last.end = Math.max(last.end, span.end);
    last.severity = moreSevere.severity;
    if (moreSevere !== last) {
      last.category = moreSevere.category;
      last.label = moreSevere.label;
      last.source = moreSevere.source;
      last.why = moreSevere.why;
    }
  }

  return merged;
}

/** Placeholder prefix per category, so the redacted text stays readable. */
const PREFIX = {
  PRIVATE_KEY: 'PRIVATE_KEY',
  AWS_KEY: 'AWS_KEY',
  AWS_SECRET: 'AWS_SECRET',
  GITHUB_TOKEN: 'GITHUB_TOKEN',
  OPENAI_KEY: 'API_KEY',
  STRIPE_KEY: 'STRIPE_KEY',
  GOOGLE_KEY: 'GOOGLE_KEY',
  SLACK_TOKEN: 'SLACK_TOKEN',
  JWT: 'JWT',
  DB_URL: 'DATABASE_URL',
  URL_TOKEN: 'URL',
  ENV_SECRET: 'SECRET',
  BEARER_TOKEN: 'BEARER_TOKEN',
  CARD: 'CARD',
  EMAIL: 'EMAIL',
  IP: 'IP',
  PHONE: 'PHONE',
  HOST: 'HOST',
  HIGH_ENTROPY: 'SECRET',
  PERSON: 'PERSON',
  CUSTOMER: 'CUSTOMER',
  PROJECT: 'PROJECT',
  ADDRESS: 'ADDRESS',
  PRIVATE_URL: 'URL',
  ACCOUNT: 'ACCOUNT',
  CONFIDENTIAL: 'CONFIDENTIAL',
  CONTEXT: 'REDACTED',
};

/**
 * Assign stable placeholders. The same literal value always gets the same
 * placeholder, so a reader can still follow the thread ("this is the same key
 * as before") without seeing the value.
 *
 * @param {string} text
 * @param {Span[]} spans
 * @param {{mode?: 'placeholder'|'mask'}} [options]
 */
export function redact(text, spans, options = {}) {
  const mode = options.mode ?? 'placeholder';
  const merged = mergeSpans(spans);
  const seen = new Map();
  const counters = new Map();
  /** @type {Array<Span & {placeholder: string, value: string}>} */
  const applied = [];

  let cursor = 0;
  let out = '';

  for (const span of merged) {
    const value = text.slice(span.start, span.end);
    let placeholder;

    if (mode === 'mask') {
      placeholder = '█'.repeat(Math.min(value.length, 24));
    } else {
      const key = `${span.category}\u0000${value}`;
      if (seen.has(key)) {
        placeholder = seen.get(key);
      } else {
        const prefix = PREFIX[span.category] ?? 'REDACTED';
        const n = (counters.get(prefix) ?? 0) + 1;
        counters.set(prefix, n);
        placeholder = `[${prefix}_${n}]`;
        seen.set(key, placeholder);
      }
    }

    out += text.slice(cursor, span.start) + placeholder;
    cursor = span.end;
    applied.push({ ...span, placeholder, value });
  }

  out += text.slice(cursor);

  return {
    text: out,
    spans: merged,
    applied,
    stats: summarise(merged),
  };
}

/**
 * Counts by category and severity, for the UI header and the CLI summary.
 * @param {Span[]} spans
 */
export function summarise(spans) {
  /** @type {Record<string, number>} */
  const byCategory = {};
  /** @type {Record<string, number>} */
  const bySeverity = { low: 0, medium: 0, high: 0, critical: 0 };
  /** @type {Record<string, number>} */
  const bySource = {};

  for (const span of spans) {
    byCategory[span.label] = (byCategory[span.label] ?? 0) + 1;
    bySeverity[span.severity] += 1;
    bySource[span.source] = (bySource[span.source] ?? 0) + 1;
  }

  return { total: spans.length, byCategory, bySeverity, bySource };
}

/**
 * What a reviewer should look at before sending. Cheap heuristics, not a promise.
 * @param {string} text
 * @param {Span[]} spans
 */
export function residualRisk(text, spans) {
  const merged = mergeSpans(spans);
  const covered = merged.reduce((sum, s) => sum + (s.end - s.start), 0);
  const ratio = text.length === 0 ? 0 : covered / text.length;

  const warnings = [];
  if (/\/Users\/[^/\s]+|\/home\/[^/\s]+|[A-Z]:\\Users\\[^\\\s]+/.test(text)) {
    warnings.push('Local filesystem paths can reveal your username and machine layout.');
  }
  if (/\b(?:patient|diagnosis|prescription|ssn|social security|passport)\b/i.test(text)) {
    warnings.push('Text mentions identity or health terms. Those carry their own rules.');
  }
  if (/\b(?:nda|confidential|internal only|do not distribute)\b/i.test(text)) {
    warnings.push('Document is marked confidential. Check your agreement before sending it anywhere.');
  }

  return {
    redactedRatio: Number(ratio.toFixed(3)),
    warnings,
  };
}
