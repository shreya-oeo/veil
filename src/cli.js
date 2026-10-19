#!/usr/bin/env node
/**
 * veil — a local-first redaction gate.
 *
 * Commands:
 *   scan [file]     report what would leak, change nothing
 *   redact [file]   write the redacted text
 *   serve           open the local UI on 127.0.0.1
 *   doctor          check Node, Ollama, and the configured model
 *
 * stdin is used when the file argument is `-` or omitted and stdin is piped.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { scan } from './pipeline.js';
import { createClient } from './model.js';
import { explain } from './context.js';
import { RULE_COUNT } from './detectors.js';
import { serve } from './server.js';

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const VERSION = '0.1.0';

const HELP = `veil ${VERSION} — redact secrets and sensitive context before you paste text into an AI.

Usage
  veil scan   [file] [options]     report findings, change nothing
  veil redact [file] [options]     print or write the redacted text
  veil serve  [--port 4317]        local UI, bound to 127.0.0.1
  veil doctor                      check Node, Ollama, and the model

Options
  --model              also run the local model pass (semantic leaks)
  --model-name <name>  Ollama model to use (default: $VEIL_MODEL or gemma3:4b)
  --host <url>         Ollama base URL (default: $OLLAMA_HOST or 127.0.0.1:11434)
  --mode <mode>        placeholder (default) or mask
  --json               machine-readable output
  --explain            ask the model for a short risk note (implies --model)
  --fail-on <level>    exit 1 when a finding at or above this severity exists
  --out <file>         redact only: write to a file instead of stdout
  --no-color           plain text output

Examples
  veil scan notes.md
  git diff | veil redact --model > safe.diff
  veil scan config.env --json --fail-on high
  veil serve

Exit codes
  0  clean (or below --fail-on)
  1  findings at or above the threshold
  2  usage or runtime error
`;

/**
 * @typedef {Object} Flags
 * @property {string[]} positional
 * @property {boolean} model
 * @property {boolean} json
 * @property {boolean} explain
 * @property {boolean} color
 * @property {string} [modelName]
 * @property {string} [host]
 * @property {'placeholder'|'mask'} mode
 * @property {string} [failOn]
 * @property {string} [out]
 * @property {number} port
 */

/** @param {string[]} argv @returns {Flags} */
function parseFlags(argv) {
  /** @type {Flags} */
  const flags = {
    positional: [],
    model: false,
    json: false,
    explain: false,
    color: process.stdout.isTTY === true && !process.env.NO_COLOR,
    mode: 'placeholder',
    port: 4317,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--model':
        flags.model = true;
        break;
      case '--json':
        flags.json = true;
        flags.color = false;
        break;
      case '--explain':
        flags.explain = true;
        flags.model = true;
        break;
      case '--no-color':
        flags.color = false;
        break;
      case '--model-name':
        flags.modelName = argv[++i];
        break;
      case '--host':
        flags.host = argv[++i];
        break;
      case '--mode': {
        const value = argv[++i];
        if (value !== 'placeholder' && value !== 'mask') {
          throw new UsageError(`--mode must be "placeholder" or "mask", got "${value}".`);
        }
        flags.mode = value;
        break;
      }
      case '--fail-on': {
        const value = argv[++i];
        if (!SEVERITIES.includes(value)) {
          throw new UsageError(`--fail-on must be one of ${SEVERITIES.join(', ')}.`);
        }
        flags.failOn = value;
        break;
      }
      case '--out':
        flags.out = argv[++i];
        break;
      case '--port': {
        const value = Number(argv[++i]);
        if (!Number.isInteger(value) || value < 1 || value > 65535) {
          throw new UsageError('--port must be an integer between 1 and 65535.');
        }
        flags.port = value;
        break;
      }
      case '--help':
      case '-h':
        process.stdout.write(HELP);
        process.exit(0);
        break;
      case '--version':
      case '-v':
        process.stdout.write(`${VERSION}\n`);
        process.exit(0);
        break;
      default:
        if (arg.startsWith('-') && arg !== '-') {
          throw new UsageError(`Unknown option "${arg}". Try --help.`);
        }
        flags.positional.push(arg);
    }
  }

  return flags;
}

class UsageError extends Error {}

/**
 * Read the input text. `-` means stdin; no argument means stdin when piped,
 * otherwise the help text, because a bare `veil scan` in a terminal is almost
 * always someone looking for the syntax.
 *
 * @param {string | undefined} target
 * @returns {Promise<{text: string, name: string}>}
 */
async function readInput(target) {
  if (target && target !== '-') {
    const resolved = path.resolve(target);
    const text = await readFile(resolved, 'utf8');
    return { text, name: path.basename(resolved) };
  }

  if (process.stdin.isTTY) {
    throw new UsageError('No input. Pass a file, or pipe text: `cat notes.md | veil scan -`.');
  }

  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return { text: Buffer.concat(chunks).toString('utf8'), name: 'stdin' };
}

/** @param {string} text @param {boolean} color */
function severityColor(text, color) {
  if (!color) return text;
  const code = { low: 36, medium: 33, high: 35, critical: 31 }[text] ?? 0;
  return `\u001b[${code}m${text}\u001b[0m`;
}

/**
 * @param {import('./detectors.js').Span[]} spans
 * @param {string} text
 * @param {boolean} color
 */
function formatTable(spans, text, color) {
  const rows = spans.map((span, index) => {
    const before = text.slice(Math.max(0, span.start - 24), span.start);
    const value = text.slice(span.start, span.end);
    const after = text.slice(span.end, span.end + 24);
    const context = `${before.replace(/\s+/g, ' ')}${value}${after.replace(/\s+/g, ' ')}`
      .trim()
      .slice(0, 64);
    return [
      String(index + 1),
      span.severity,
      span.source,
      span.label,
      `${span.start}-${span.end}`,
      context,
    ];
  });

  const headers = ['#', 'severity', 'source', 'finding', 'offset', 'context'];
  const widths = headers.map((header, i) =>
    Math.max(header.length, ...rows.map((row) => row[i].length)),
  );

  const line = (cells) =>
    cells
      .map((cell, i) => (i === cells.length - 1 ? cell : cell.padEnd(widths[i])))
      .join('  ')
      .trimEnd();

  const output = [line(headers), widths.map((w) => '─'.repeat(w)).join('  ')];
  for (const row of rows) {
    output.push(line(row.map((cell, i) => (i === 1 ? severityColor(cell, color) : cell))));
  }
  return output.join('\n');
}

/** @param {ReturnType<typeof scan> extends Promise<infer T> ? T : never} result */
function printSummary(result, color) {
  const { stats, residual, model, timingMs } = result;
  const lines = [];

  if (stats.total === 0) {
    lines.push('No findings. That is not a guarantee: read it once yourself.');
  } else {
    const parts = Object.entries(stats.bySeverity)
      .filter(([, count]) => count > 0)
      .map(([severity, count]) => `${count} ${severity}`);
    lines.push(`${stats.total} finding(s): ${parts.join(', ')} · ${timingMs} ms`);
    const sources = Object.entries(stats.bySource)
      .map(([source, count]) => `${count} ${source}`)
      .join(', ');
    lines.push(`Sources: ${sources}. ${RULE_COUNT} deterministic rules + entropy scan.`);
  }

  if (model.used) {
    if (model.error) {
      lines.push(severityColor(`Model pass unavailable: ${model.error}`, color));
    } else {
      lines.push(
        `Model pass: kept ${stats.bySource.model ?? 0} verified quote(s), dropped ${model.dropped} that did not appear verbatim in the input.`,
      );
    }
  }

  for (const warning of residual.warnings) lines.push(severityColor(`! ${warning}`, color));

  return lines.join('\n');
}

/** @param {string[]} argv */
async function main(argv) {
  const [command, ...rest] = argv;
  const flags = parseFlags(rest);

  if (!command || command === 'help') {
    process.stdout.write(HELP);
    return 0;
  }

  if (!['scan', 'redact', 'serve', 'doctor'].includes(command)) {
    throw new UsageError(`Unknown command "${command}". Try --help.`);
  }

  if (command === 'serve') {
    await serve({ port: flags.port });
    return 0;
  }

  if (command === 'doctor') {
    return await doctor(flags);
  }

  const { text, name } = await readInput(flags.positional[0]);

  const client = createClient({
    host: flags.host,
    model: flags.modelName,
  });

  const result = await scan(text, {
    client,
    useModel: flags.model,
    mode: flags.mode,
  });

  const riskNote =
    flags.explain && flags.model
      ? await explain(client, result.text, result.spans)
      : undefined;

  const threshold = flags.failOn ?? (command === 'scan' ? 'low' : undefined);
  const shouldFail =
    threshold !== undefined &&
    result.spans.some(
      (span) => SEVERITIES.indexOf(span.severity) >= SEVERITIES.indexOf(threshold),
    );

  if (command === 'redact') {
    if (flags.out) {
      await writeFile(path.resolve(flags.out), result.text, 'utf8');
      if (!flags.json) {
        process.stderr.write(
          `Wrote ${result.text.length} chars to ${flags.out} (${result.stats.total} redactions).\n`,
        );
      }
    } else if (!flags.json) {
      process.stdout.write(result.text.endsWith('\n') ? result.text : `${result.text}\n`);
    }
  }

  if (flags.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          input: name,
          mode: flags.mode,
          redacted: command === 'redact' ? result.text : undefined,
          findings: result.applied.map((span) => ({
            category: span.category,
            label: span.label,
            severity: span.severity,
            source: span.source,
            start: span.start,
            end: span.end,
            placeholder: span.placeholder,
          })),
          stats: result.stats,
          residual: result.residual,
          model: result.model,
          timingMs: result.timingMs,
          riskNote,
        },
        null,
        2,
      )}\n`,
    );
  } else {
    if (command === 'scan') {
      if (result.spans.length > 0) {
        process.stdout.write(`${formatTable(result.spans, text, flags.color)}\n\n`);
      }
      process.stdout.write(`${printSummary(result, flags.color)}\n`);
    } else {
      process.stderr.write(`${printSummary(result, flags.color)}\n`);
    }
    if (riskNote) process.stderr.write(`\n${riskNote}\n`);
  }

  return shouldFail ? 1 : 0;
}

/** @param {Flags} flags */
async function doctor(flags) {
  const lines = [];
  const nodeMajor = Number(process.versions.node.split('.')[0]);
  lines.push(`node      ${process.versions.node} ${nodeMajor >= 20 ? 'ok' : '— need >= 20'}`);

  const client = createClient({ host: flags.host, model: flags.modelName });
  const health = await client.health();

  if (!health.reachable) {
    lines.push(`ollama    unreachable at ${client.host} (${health.error})`);
    lines.push('          deterministic + entropy passes still work without it.');
  } else {
    lines.push(`ollama    reachable at ${client.host}`);
    lines.push(`model     ${client.model}`);
    const present = health.models.includes(client.model);
    lines.push(
      `          ${present ? 'present' : `not pulled — run: ollama pull ${client.model}`}`,
    );
    const others = health.models.filter((m) => m !== client.model);
    if (others.length > 0) {
      lines.push(`available ${others.slice(0, 8).join(', ')}${others.length > 8 ? ', …' : ''}`);
    }
    if (client.model.endsWith(':cloud')) {
      lines.push(
        'note      this is a cloud-routed tag. Veil still sends text only to the',
      );
      lines.push('          Ollama endpoint you configured, but inference is not on this machine.');
    }
  }

  lines.push(`rules     ${RULE_COUNT} deterministic detectors + entropy scan`);
  lines.push(`ui        ${existsSync(path.resolve('public/index.html')) ? 'public/index.html' : 'missing'}`);
  process.stdout.write(`${lines.join('\n')}\n`);
  return health.reachable ? 0 : 0;
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (error) {
  if (error instanceof UsageError) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
  } else {
    process.stderr.write(`${error?.stack ?? error}\n`);
    process.exitCode = 2;
  }
}
