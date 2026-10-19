/**
 * The model pass.
 *
 * Regex finds shapes. The model finds meaning: a customer's name, an internal
 * project, the one line of a contract that says more than it should. It runs
 * second and its output is treated as a *suggestion*, not a verdict.
 *
 * The whole design rests on one rule: the model may only return substrings that
 * literally appear in the input. Anything else is dropped. Small models love to
 * "helpfully" rewrite a quote or invent a plausible-looking secret, and a
 * redactor that edits the user's text based on an invented span is worse than
 * no redactor at all.
 */

/** @typedef {import('./detectors.js').Span} Span */

const SYSTEM = `You are a privacy reviewer. You read text a developer is about to paste into an AI chat and you find the parts that identify a person, a customer, a company, or an internal system.

You do not find API keys, passwords, tokens, or card numbers. Another tool already does that with exact rules. You are looking for the things only reading can catch:
- A person's full name, when it identifies a real individual
- A customer, company, or client name that is not public
- An internal project, codename, or hostname
- A physical address, or a location precise enough to find someone
- A private URL, ticket ID, or account number
- Text that is confidential or under NDA

Rules:
1. Every quote MUST be copied character-for-character from the input. Do not fix spelling, do not shorten with ellipses, do not paraphrase.
2. Quote the smallest fragment that makes the point. "Priya Raman" not the whole sentence.
3. Do not flag public products, open-source project names, the user's own tooling, or generic words.
4. Categories: PERSON, CUSTOMER, PROJECT, ADDRESS, PRIVATE_URL, ACCOUNT, CONFIDENTIAL.
5. If nothing qualifies, return an empty list. An empty list is a good answer.

Respond with JSON only:
{"findings":[{"quote":"exact text from input","category":"PERSON","reason":"one short sentence"}]}`;

/**
 * Ask the model for sensitive spans, then keep only the ones that survive
 * verification against the source text.
 *
 * @param {import('./model.js').createClient} client
 * @param {string} text
 * @param {{timeoutMs?: number}} [options]
 * @returns {Promise<{spans: Span[], dropped: number, error?: string}>}
 */
export async function detectWithModel(client, text, options = {}) {
  const excerpt = text.length > 6000 ? `${text.slice(0, 6000)}\n\n[truncated]` : text;

  let result;
  try {
    result = await client.json({
      system: SYSTEM,
      prompt: `Text to review:\n\n"""\n${excerpt}\n"""`,
      timeoutMs: options.timeoutMs ?? 120_000,
    });
  } catch (error) {
    return { spans: [], dropped: 0, error: error.message };
  }

  const findings = Array.isArray(result?.findings) ? result.findings : [];
  const spans = [];
  let dropped = 0;

  for (const finding of findings) {
    const quote = typeof finding?.quote === 'string' ? finding.quote.trim() : '';
    if (quote.length < 2) {
      dropped += 1;
      continue;
    }

    // Verify: the quote must exist verbatim in the text. Search from the start
    // each time; a repeated quote is fine, it just gets deduped by mergeSpans.
    const index = text.indexOf(quote);
    if (index === -1) {
      dropped += 1;
      continue;
    }

    const category = normaliseCategory(finding?.category);
    spans.push({
      start: index,
      end: index + quote.length,
      category,
      label: LABELS[category],
      severity: category === 'PERSON' || category === 'ACCOUNT' ? 'high' : 'medium',
      source: 'model',
      why: typeof finding?.reason === 'string' ? finding.reason.slice(0, 200) : undefined,
    });
  }

  return { spans, dropped };
}

const LABELS = {
  PERSON: 'Person name',
  CUSTOMER: 'Customer or client name',
  PROJECT: 'Internal project or codename',
  ADDRESS: 'Address or precise location',
  PRIVATE_URL: 'Private link or ticket',
  ACCOUNT: 'Account identifier',
  CONFIDENTIAL: 'Confidential material',
};

function normaliseCategory(value) {
  const upper = String(value ?? '').toUpperCase();
  return LABELS[upper] ? upper : 'CONFIDENTIAL';
}

/**
 * A plain-language risk note, generated from the findings we already trust.
 * This never sees the original text, only the redacted one, so the explanation
 * cannot leak back.
 *
 * @param {import('./model.js').createClient} client
 * @param {string} redactedText
 * @param {Span[]} spans
 */
export async function explain(client, redactedText, spans) {
  const summary = spans
    .map((s) => `- ${s.label}${s.why ? `: ${s.why}` : ''}`)
    .join('\n');

  if (!summary) {
    return 'Nothing sensitive was found. As always: read the text once yourself before you send it.';
  }

  try {
    return await client.text({
      system:
        'You are a careful security reviewer. Be concrete and short. Never invent details that are not in the summary.',
      prompt: `I redacted this text before pasting it into an AI. Findings:\n${summary}\n\nRedacted text:\n"""\n${redactedText.slice(0, 2000)}\n"""\n\nIn three sentences, tell me what is still risky about sending this, and what I should double-check.`,
      timeoutMs: 60_000,
    });
  } catch {
    return `${spans.length} item(s) redacted. Re-read the result before sending; the model was unavailable so this note was not generated.`;
  }
}
