import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { scan } from '../src/pipeline.js';
import { FAKE, DB_URL, SUPPORT_EMAIL } from '../fixtures/fakes.js';

const fixture = new URL('../fixtures/support-ticket.md', import.meta.url);

test('scan runs without a model and without network access', async () => {
  const text = await readFile(fixture, 'utf8');
  const result = await scan(text);

  assert.equal(result.model.used, false);
  assert.ok(result.stats.total > 5, `expected findings, got ${result.stats.total}`);
  assert.ok(result.text.length > 0);
});

test('no high-severity literal survives the redaction', async () => {
  const text = await readFile(fixture, 'utf8');
  const result = await scan(text);

  const secrets = [
    FAKE.awsKeyId,
    FAKE.awsSecret,
    FAKE.githubToken,
    FAKE.stripeKey,
    SUPPORT_EMAIL,
    FAKE.luhnCard,
    '10.42.7.19',
    DB_URL,
  ];

  for (const secret of secrets) {
    assert.equal(result.text.includes(secret), false, `leaked: ${secret}`);
  }
});

test('redacted text keeps the shape of the document', async () => {
  const text = await readFile(fixture, 'utf8');
  const result = await scan(text);

  assert.ok(result.text.includes('# Billing migration — staging notes'));
  assert.ok(result.text.includes('Customer:'));
  assert.ok(/\[EMAIL_\d+\]/.test(result.text));
  assert.ok(/\[AWS_KEY_\d+\]/.test(result.text));
  assert.ok(/\[PHONE_\d+\]/.test(result.text));
});

test('every applied span points at text that was actually removed', async () => {
  const text = await readFile(fixture, 'utf8');
  const result = await scan(text);

  for (const span of result.applied) {
    const original = text.slice(span.start, span.end);
    assert.ok(original.length > 0);
    assert.equal(result.text.includes(original) && original.length > 20, false);
  }
});

test('clean text produces no findings and no placeholders', async () => {
  const text = 'The build finished in 4.2 seconds. Nothing here identifies anyone.';
  const result = await scan(text);

  assert.equal(result.stats.total, 0);
  assert.equal(result.text, text);
  assert.equal(result.residual.warnings.length, 0);
});

test('mask mode removes the original values too', async () => {
  const result = await scan(`mail ${SUPPORT_EMAIL} today`, { mode: 'mask' });
  assert.equal(result.text.includes('priya.raman'), false);
  assert.ok(result.text.includes('█'));
});

test('a model error degrades to deterministic findings instead of throwing', async () => {
  const broken = {
    async json() {
      throw new Error('Ollama is not running');
    },
  };

  const result = await scan('mail priya@example.com', { client: broken, useModel: true });
  assert.equal(result.model.used, true);
  assert.equal(result.model.error, 'Ollama is not running');
  assert.ok(result.stats.total >= 1);
});

test('the model can add a finding, and invented quotes are dropped', async () => {
  const text = 'Priya Raman says the migration is blocked.';
  const client = {
    async json() {
      return {
        findings: [
          { quote: 'Priya Raman', category: 'PERSON', reason: 'Identifies a customer' },
          { quote: 'Priya Raman-Sharma', category: 'PERSON', reason: 'Invented, not in the text' },
        ],
      };
    },
  };

  const result = await scan(text, { client, useModel: true });
  assert.equal(result.model.dropped, 1);
  assert.equal(result.text, '[PERSON_1] says the migration is blocked.');
  assert.deepEqual(result.stats.bySource, { model: 1 });
});

test('a model quote that only differs by whitespace is rejected', async () => {
  const text = 'Priya Raman says hello.';
  const client = {
    async json() {
      return { findings: [{ quote: 'Priya  Raman', category: 'PERSON' }] };
    },
  };

  const result = await scan(text, { client, useModel: true });
  assert.equal(result.model.dropped, 1);
  assert.equal(result.text, text);
});
