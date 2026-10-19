/**
 * Pipeline: rules -> entropy -> model -> merge -> redact.
 *
 * Each stage is optional except the deterministic ones, so the tool still works
 * with the network off and no model pulled.
 */

import { detectWithRules } from './detectors.js';
import { detectHighEntropy } from './entropy.js';
import { detectWithModel } from './context.js';
import { mergeSpans, redact, residualRisk } from './redact.js';

/**
 * @param {string} text
 * @param {{client?: ReturnType<import('./model.js').createClient>, useModel?: boolean, mode?: 'placeholder'|'mask'}} [options]
 */
export async function scan(text, options = {}) {
  const started = Date.now();
  const ruleSpans = detectWithRules(text);
  const entropySpans = detectHighEntropy(text);

  let modelSpans = [];
  let modelError;
  let dropped = 0;

  if (options.useModel && options.client) {
    const result = await detectWithModel(options.client, text);
    dropped = result.dropped;
    modelError = result.error;

    // The model sometimes repeats what a rule already found, with a coarser
    // label ("Person name" over an email address) and a stray trailing period.
    // If a deterministic span covers most of the quote, keep the precise one.
    const known = [...ruleSpans, ...entropySpans];
    const coveredByRule = (candidate) =>
      known.some((span) => {
        const overlap = Math.min(span.end, candidate.end) - Math.max(span.start, candidate.start);
        if (overlap <= 0) return false;
        const shorter = Math.min(span.end - span.start, candidate.end - candidate.start);
        return overlap / shorter >= 0.8;
      });
    modelSpans = result.spans.filter((candidate) => !coveredByRule(candidate));
  }

  const spans = mergeSpans([...ruleSpans, ...entropySpans, ...modelSpans]);
  const result = redact(text, spans, { mode: options.mode });
  const risk = residualRisk(text, spans);

  return {
    ...result,
    residual: risk,
    timingMs: Date.now() - started,
    model: options.useModel
      ? { used: true, dropped, error: modelError }
      : { used: false, dropped: 0 },
  };
}

export { detectWithRules, detectHighEntropy, detectWithModel, mergeSpans, redact };
