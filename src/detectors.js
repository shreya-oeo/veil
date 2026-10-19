/**
 * Deterministic detectors.
 *
 * These run before the model and they are the floor, not the ceiling: a regex
 * can find an AWS key with certainty, and no amount of prompt engineering makes
 * a 3B model better at that than `/\bAKIA[0-9A-Z]{16}\b/`.
 *
 * Every rule returns spans as {start, end, category, label, severity, source}.
 * Spans are half-open: [start, end).
 */

/** @typedef {'low'|'medium'|'high'|'critical'} Severity */

/**
 * @typedef {Object} Span
 * @property {number} start
 * @property {number} end
 * @property {string} category  machine name, used for grouping and placeholder prefixes
 * @property {string} label     human name shown in the UI
 * @property {Severity} severity
 * @property {'regex'|'entropy'|'model'} source
 * @property {string} [why]     optional one-line explanation
 */

const RULES = [
  {
    id: 'private-key',
    category: 'PRIVATE_KEY',
    label: 'Private key block',
    severity: 'critical',
    // Whole PEM block, including the body, because a truncated key is still a leak.
    pattern:
      /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----[\s\S]{0,4000}?-----END (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g,
  },
  {
    id: 'aws-access-key',
    category: 'AWS_KEY',
    label: 'AWS access key ID',
    severity: 'critical',
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  },
  {
    id: 'aws-secret',
    category: 'AWS_SECRET',
    label: 'AWS secret access key',
    severity: 'critical',
    pattern: /\baws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    group: 1,
  },
  {
    id: 'github-token',
    category: 'GITHUB_TOKEN',
    label: 'GitHub token',
    severity: 'critical',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
  },
  {
    id: 'openai-key',
    category: 'OPENAI_KEY',
    label: 'OpenAI-style API key',
    severity: 'critical',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: 'stripe-key',
    category: 'STRIPE_KEY',
    label: 'Stripe secret key',
    severity: 'critical',
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  },
  {
    id: 'google-api-key',
    category: 'GOOGLE_KEY',
    label: 'Google API key',
    severity: 'high',
    pattern: /\bAIza[0-9A-Za-z_-]{35,39}\b/g,
  },
  {
    id: 'slack-token',
    category: 'SLACK_TOKEN',
    label: 'Slack token',
    severity: 'critical',
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    id: 'jwt',
    category: 'JWT',
    label: 'JSON Web Token',
    severity: 'high',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    id: 'db-url',
    category: 'DB_URL',
    label: 'Database URL with credentials',
    severity: 'critical',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s:@/]+:[^\s@/]+@[^\s/]+(?:\/[^\s]*)?/gi,
  },
  {
    id: 'url-with-token',
    category: 'URL_TOKEN',
    label: 'URL containing a credential',
    severity: 'high',
    pattern:
      /\bhttps?:\/\/[^\s"'<>]*?(?:[?&](?:token|key|api_key|apikey|access_token|sig|signature|password)=)[^\s"'&#]+/gi,
  },
  {
    id: 'env-secret',
    category: 'ENV_SECRET',
    label: 'Secret assigned in an env-style line',
    severity: 'high',
    // SECRET / TOKEN / PASSWORD / KEY = something that is not an obvious placeholder.
    pattern:
      /^[ \t]*(?:export[ \t]+)?([A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*)[ \t]*[:=][ \t]*["']?([^\s"'#]{6,})["']?/gm,
    group: 2,
    // Values that are clearly placeholders, not credentials.
    ignore: /^(?:x{3,}|\*{3,}|\.{3,}|<.*>|\$\{.*\}|changeme|replace[-_]?me|your[-_].*|example.*|dummy.*|test.*|null|none|true|false|0)$/i,
  },
  {
    id: 'bearer',
    category: 'BEARER_TOKEN',
    label: 'Bearer token in a header or curl command',
    severity: 'high',
    pattern: /\bBearer\s+([A-Za-z0-9\-._~+/]{16,}=*)/g,
    group: 1,
  },
  {
    id: 'credit-card',
    category: 'CARD',
    label: 'Payment card number',
    severity: 'critical',
    pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: (value) => luhn(value.replace(/\D/g, '')),
  },
  {
    id: 'email',
    category: 'EMAIL',
    label: 'Email address',
    severity: 'medium',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    id: 'ipv4',
    category: 'IP',
    label: 'IPv4 address',
    severity: 'low',
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    // Documentation ranges and loopback are noise, not leaks.
    ignore: /^(?:127\.|0\.0\.0\.0$|255\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/,
  },
  {
    id: 'phone',
    category: 'PHONE',
    label: 'Phone number',
    severity: 'medium',
    pattern: /(?<![\w.-])(?:\+\d{1,3}[ -]?)?(?:\(\d{3}\)[ -]?|\d{3}[ -])\d{3}[ -]\d{4}(?![\w.-])/g,
  },
  {
    id: 'internal-host',
    category: 'HOST',
    label: 'Internal hostname',
    severity: 'medium',
    // db-prod-01, redis.internal, staging-api.corp.example — the shapes that leak topology.
    pattern:
      /\b(?:[a-z0-9][a-z0-9-]{0,62}\.)+(?:internal|local|localdomain|lan|corp|intranet|svc|cluster\.local)\b/gi,
  },
];

/**
 * Luhn check. Keeps the card rule from firing on order IDs and timestamps.
 * @param {string} digits
 */
export function luhn(digits) {
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = Number(digits[i]);
    if (Number.isNaN(d)) return false;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * Run every deterministic rule over `text`.
 * @param {string} text
 * @returns {Span[]}
 */
export function detectWithRules(text) {
  /** @type {Span[]} */
  const spans = [];

  for (const rule of RULES) {
    // Fresh lastIndex per call: these regexes are module-level and `g`-flagged.
    rule.pattern.lastIndex = 0;
    let match;
    while ((match = rule.pattern.exec(text)) !== null) {
      const captured = rule.group ? match[rule.group] : match[0];
      if (captured === undefined) continue;

      if (rule.ignore && rule.ignore.test(captured)) continue;
      if (rule.validate && !rule.validate(captured)) continue;

      // Work out where the captured group sits inside the full match.
      let start = match.index;
      let end = match.index + match[0].length;
      if (rule.group) {
        const offset = match[0].indexOf(captured);
        if (offset === -1) continue;
        start = match.index + offset;
        end = start + captured.length;
      }

      spans.push({
        start,
        end,
        category: rule.category,
        label: rule.label,
        severity: rule.severity,
        source: 'regex',
      });

      // Zero-length matches would spin forever.
      if (match[0].length === 0) rule.pattern.lastIndex += 1;
    }
  }

  return spans;
}

export const RULE_COUNT = RULES.length;
export const RULE_IDS = RULES.map((r) => r.id);
