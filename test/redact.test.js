import test from 'node:test';
import assert from 'node:assert/strict';

import { detectHighEntropy, shannonEntropy } from '../src/entropy.js';
import { mergeSpans, redact, summarise, residualRisk } from '../src/redact.js';
import { FAKE } from '../fixtures/fakes.js';

test('shannon entropy is 0 for a single repeated character', () => {
  assert.equal(shannonEntropy('aaaaaaaa'), 0);
  assert.ok(shannonEntropy('aA1!bB2@') > 2.5);
});

test('flags a random-looking 32 character value', () => {
  const token = FAKE.entropyToken;
  const spans = detectHighEntropy(`key = ${token}`);
  assert.equal(spans.length, 1);
  assert.equal(spans[0].category, 'HIGH_ENTROPY');
});

test('does not flag a git SHA or a sentence', () => {
  const sha = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3';
  assert.equal(detectHighEntropy(`commit ${sha}`).length, 0);
  assert.equal(detectHighEntropy('the quick brown fox jumps over the lazy dog').length, 0);
});

test('does not flag a long value made of one character class', () => {
  assert.equal(detectHighEntropy('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa').length, 0);
});

test('merges overlapping spans into one', () => {
  const merged = mergeSpans([
    { start: 0, end: 10, category: 'A', label: 'A', severity: 'medium', source: 'regex' },
    { start: 5, end: 20, category: 'B', label: 'B', severity: 'critical', source: 'entropy' },
  ]);

  assert.equal(merged.length, 1);
  assert.equal(merged[0].start, 0);
  assert.equal(merged[0].end, 20);
  assert.equal(merged[0].severity, 'critical');
});

test('keeps adjacent but non-overlapping spans separate', () => {
  const merged = mergeSpans([
    { start: 0, end: 5, category: 'A', label: 'A', severity: 'low', source: 'regex' },
    { start: 6, end: 10, category: 'B', label: 'B', severity: 'low', source: 'regex' },
  ]);
  assert.equal(merged.length, 2);
});

test('drops inverted and zero-width spans', () => {
  const merged = mergeSpans([
    { start: 5, end: 5, category: 'A', label: 'A', severity: 'low', source: 'regex' },
    { start: 9, end: 2, category: 'B', label: 'B', severity: 'low', source: 'regex' },
  ]);
  assert.equal(merged.length, 0);
});

test('reuses one placeholder for a repeated value', () => {
  const text = 'write to a@example.com, then again to a@example.com';
  const first = text.indexOf('a@example.com');
  const second = text.indexOf('a@example.com', first + 1);
  const spans = [first, second].map((start) => ({
    start,
    end: start + 'a@example.com'.length,
    category: 'EMAIL',
    label: 'Email',
    severity: 'medium',
    source: 'regex',
  }));
  const result = redact(text, spans);
  const placeholders = result.applied.map((span) => span.placeholder);
  assert.deepEqual(placeholders, ['[EMAIL_1]', '[EMAIL_1]']);
  assert.equal(result.text.includes('a@example.com'), false);
});

test('numbers different values of the same category', () => {
  const text = 'a@one.example b@two.example';
  const spans = [
    { start: 0, end: 13, category: 'EMAIL', label: 'Email', severity: 'medium', source: 'regex' },
    { start: 14, end: 27, category: 'EMAIL', label: 'Email', severity: 'medium', source: 'regex' },
  ];
  const result = redact(text, spans);
  assert.deepEqual(
    result.applied.map((span) => span.placeholder),
    ['[EMAIL_1]', '[EMAIL_2]'],
  );
});

test('mask mode preserves length up to a cap', () => {
  const text = 'secret=abcdefghijklmnopqrstuvwxyz';
  const result = redact(text, [
    { start: 7, end: text.length, category: 'ENV_SECRET', label: 'Secret', severity: 'high', source: 'regex' },
  ], { mode: 'mask' });
  assert.equal(result.text.startsWith('secret='), true);
  assert.equal(result.text.includes('a'), false);
});

test('summarise counts by severity and source', () => {
  const stats = summarise([
    { start: 0, end: 1, category: 'A', label: 'A', severity: 'critical', source: 'regex' },
    { start: 2, end: 3, category: 'B', label: 'B', severity: 'medium', source: 'model' },
    { start: 4, end: 5, category: 'B', label: 'B', severity: 'critical', source: 'entropy' },
  ]);

  assert.equal(stats.total, 3);
  assert.equal(stats.bySeverity.critical, 2);
  assert.equal(stats.byCategory.B, 2);
  assert.equal(stats.bySource.model, 1);
});

test('residual risk warns about paths, health terms, and NDA language', () => {
  const risk = residualRisk('see /Users/jan/notes.txt for the NDA text about a patient', []);
  assert.equal(risk.warnings.length, 3);
  assert.ok(risk.warnings.some((w) => w.includes('filesystem')));
});
