/**
 * High-entropy token detection.
 *
 * Rules catch credentials that look like credentials. This catches the ones that
 * just look like noise: a 48-character string with no vowels, sitting in a config
 * file, is almost never a word.
 *
 * Entropy alone is noisy, so the scoring is deliberately conservative and the
 * allowlist handles the two false positives that show up in every repo
 * (lockfile hashes and base64 image data).
 */

import { luhn } from './detectors.js';

/** Shannon entropy in bits per character. */
export function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Things that are long, random-looking, and harmless. */
const ALLOWLIST = [
  /^[0-9a-f]{40}$/i, // git SHA-1
  /^[0-9a-f]{64}$/i, // SHA-256
  /^sha\d{3}-[A-Za-z0-9+/=]{20,}$/, // subresource integrity
  /^data:image\/[a-z+]+;base64,/i,
  /^[A-Za-z0-9+/=]{0,8}$/,
];

/** A token has to look like a secret before entropy is even worth computing. */
const CANDIDATE = /[A-Za-z0-9+/_-]{20,}={0,2}/g;

/**
 * @param {string} text
 * @param {{threshold?: number, minLength?: number}} [options]
 * @returns {import('./detectors.js').Span[]}
 */
export function detectHighEntropy(text, options = {}) {
  const threshold = options.threshold ?? 4.3;
  const minLength = options.minLength ?? 24;
  /** @type {import('./detectors.js').Span[]} */
  const spans = [];

  CANDIDATE.lastIndex = 0;
  let match;
  while ((match = CANDIDATE.exec(text)) !== null) {
    const token = match[0];
    if (token.length < minLength) continue;
    if (ALLOWLIST.some((re) => re.test(token))) continue;

    // A single repeated character or a run of one class is not a secret.
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[+/_=-]/].filter((re) => re.test(token)).length;
    if (classes < 2) continue;
    if (luhn(token.replace(/\D/g, '')) && /\d{13,}/.test(token)) continue;

    const entropy = shannonEntropy(token);
    if (entropy < threshold) continue;

    spans.push({
      start: match.index,
      end: match.index + token.length,
      category: 'HIGH_ENTROPY',
      label: `High-entropy string (${entropy.toFixed(1)} bits/char)`,
      severity: 'high',
      source: 'entropy',
      why: 'Random-looking value with no recognisable format. Likely a key, salt, or token.',
    });
  }

  return spans;
}
