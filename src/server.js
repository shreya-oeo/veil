/**
 * Local HTTP server for the Veil UI.
 *
 * Bound to 127.0.0.1 by default. The text being checked never leaves this
 * machine except, optionally, to the Ollama endpoint you configured — which is
 * the point of the tool. There is no telemetry, no CDN, and no external font.
 */

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scan } from './pipeline.js';
import { createClient } from './model.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MAX_BODY = 2 * 1024 * 1024;

/**
 * @param {{port?: number, host?: string, open?: boolean}} [options]
 */
export async function serve(options = {}) {
  const port = options.port ?? 4317;
  const host = options.host ?? '127.0.0.1';
  const html = await readFile(path.join(ROOT, 'public', 'index.html'), 'utf8');

  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
        res.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'content-security-policy':
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'",
          'x-content-type-options': 'nosniff',
        });
        res.end(html);
        return;
      }

      if (req.method === 'GET' && req.url === '/api/health') {
        const client = createClient();
        const health = await client.health();
        return json(res, 200, {
          ok: true,
          version: '0.1.0',
          ollama: { ...health, model: client.model },
        });
      }

      if (req.method === 'POST' && req.url === '/api/scan') {
        const body = await readJson(req);
        const text = String(body?.text ?? '');
        if (!text.trim()) return json(res, 400, { error: 'Nothing to scan.' });

        const client = createClient({ model: body?.modelName || undefined });
        const result = await scan(text, {
          client,
          useModel: body?.useModel === true,
          mode: body?.mode === 'mask' ? 'mask' : 'placeholder',
        });

        return json(res, 200, {
          redacted: result.text,
          segments: segments(text, result.applied),
          findings: result.applied.map((span) => ({
            category: span.category,
            label: span.label,
            severity: span.severity,
            source: span.source,
            start: span.start,
            end: span.end,
            placeholder: span.placeholder,
            why: span.why,
          })),
          stats: result.stats,
          residual: result.residual,
          model: { ...result.model, name: client.model },
          timingMs: result.timingMs,
        });
      }

      return json(res, 404, { error: 'Not found.' });
    } catch (error) {
      const status = error?.status ?? 500;
      return json(res, status, { error: error?.message ?? 'Unexpected error.' });
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });

  process.stdout.write(`Veil is running at http://${host}:${port}\n`);
  process.stdout.write('Local only. Press Ctrl+C to stop.\n');

  const shutdown = () => server.close(() => process.exit(0));
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return server;
}

/**
 * Turn redacted text plus applied spans into renderable pieces, so the browser
 * never has to interpret offsets or build HTML from user text.
 *
 * @param {string} text
 * @param {Array<import('./detectors.js').Span & {placeholder: string}>} applied
 */
function segments(text, applied) {
  /** @type {Array<Record<string, string>>} */
  const out = [];
  let cursor = 0;

  for (const span of applied) {
    if (span.start > cursor) out.push({ type: 'text', text: text.slice(cursor, span.start) });
    out.push({
      type: 'finding',
      text: span.placeholder,
      label: span.label,
      severity: span.severity,
      source: span.source,
    });
    cursor = span.end;
  }

  if (cursor < text.length) out.push({ type: 'text', text: text.slice(cursor) });
  return out;
}

/** @param {http.ServerResponse} res */
function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
    'x-content-type-options': 'nosniff',
  });
  res.end(body);
}

/** @param {http.IncomingMessage} req */
async function readJson(req) {
  const chunks = [];
  let size = 0;

  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) {
      const error = new Error('That input is larger than 2 MB. Trim it first.');
      // @ts-expect-error - attach a status for the shared error handler
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }

  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    // @ts-expect-error - attach a status for the shared error handler
    const error = new Error('Request body was not valid JSON.');
    error.status = 400;
    throw error;
  }
}
