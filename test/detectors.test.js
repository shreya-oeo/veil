import test from 'node:test';
import assert from 'node:assert/strict';

import { detectWithRules, luhn, RULE_COUNT } from '../src/detectors.js';
import { FAKE, DB_URL } from '../fixtures/fakes.js';

const categories = (text) => detectWithRules(text).map((span) => span.category);
const values = (text) =>
  detectWithRules(text).map((span) => text.slice(span.start, span.end));

test('luhn validates real card numbers and rejects order ids', () => {
  assert.equal(luhn('4242424242424242'), true);
  assert.equal(luhn('4111111111111111'), true);
  assert.equal(luhn('1234567890123456'), false);
  assert.equal(luhn('123'), false);
});

test('the rule set is not accidentally empty', () => {
  assert.ok(RULE_COUNT >= 15, `expected at least 15 rules, found ${RULE_COUNT}`);
});

test('detects an AWS access key and its secret', () => {
  const text = [
    `AWS_ACCESS_KEY_ID=${FAKE.awsKeyId}`,
    `aws_secret_access_key = ${FAKE.awsSecret}`,
  ].join('\n');

  const found = categories(text);
  assert.ok(found.includes('AWS_KEY'));
  assert.ok(found.includes('AWS_SECRET'));
});

test('detects provider tokens by their prefixes', () => {
  const text = [
    `GITHUB_TOKEN=${FAKE.githubToken}`,
    `OPENAI_API_KEY=${FAKE.openaiKey}`,
    `STRIPE_SECRET_KEY=${FAKE.stripeKey}`,
    `SLACK_BOT_TOKEN=${FAKE.slackToken}`,
    `GOOGLE_MAPS_KEY=${FAKE.googleKey}`,
  ].join('\n');

  const found = categories(text);
  for (const category of ['GITHUB_TOKEN', 'OPENAI_KEY', 'STRIPE_KEY', 'SLACK_TOKEN', 'GOOGLE_KEY']) {
    assert.ok(found.includes(category), `missing ${category} in ${found.join(', ')}`);
  }
});

test('detects a JWT', () => {
  assert.ok(categories(`Authorization: Bearer ${FAKE.jwt}`).includes('JWT'));
});

test('detects a database URL with inline credentials', () => {
  assert.ok(categories(`DATABASE_URL=${DB_URL}`).includes('DB_URL'));
});

test('redacts an entire PEM block, not just the header', () => {
  const text = ['before', FAKE.privateKey, 'after'].join('\n');

  const spans = detectWithRules(text);
  const block = spans.find((span) => span.category === 'PRIVATE_KEY');
  assert.ok(block, 'expected a private key span');
  assert.equal(text.slice(block.start, block.end).includes(FAKE.privateKeyFooter), true);
});

test('only flags payment cards that pass the Luhn check', () => {
  assert.deepEqual(categories(`card ${FAKE.luhnCard}`), ['CARD']);
  assert.equal(categories('order 1234 5678 9012 3456').includes('CARD'), false);
});

test('ignores documentation IP ranges but keeps private ones', () => {
  assert.equal(categories('host 192.0.2.10').includes('IP'), false);
  assert.equal(categories('host 127.0.0.1').includes('IP'), false);
  assert.ok(categories('host 10.42.7.19').includes('IP'));
});

test('ignores obvious placeholder values but keeps real ones', () => {
  assert.equal(categories('API_TOKEN=<your-token-here>').includes('ENV_SECRET'), false);
  assert.equal(categories('SESSION_SECRET=changeme').includes('ENV_SECRET'), false);
  assert.ok(categories('CLIENT_SECRET=8f3a9c2e1b7d4f6a').includes('ENV_SECRET'));
});

test('detects internal hostnames, emails, and phone numbers', () => {
  const text = 'ping billing-api.corp.internal, mail priya@northwind.example, call +1 415 555 0132';
  const found = categories(text);
  assert.ok(found.includes('HOST'));
  assert.ok(found.includes('EMAIL'));
  assert.ok(found.includes('PHONE'));
});

test('span offsets point at the captured value, not the whole line', () => {
  const text = `export GITHUB_TOKEN=${FAKE.githubToken}`;
  const span = detectWithRules(text).find((s) => s.category === 'GITHUB_TOKEN');
  assert.ok(span);
  assert.equal(text.slice(span.start, span.end).startsWith('ghp_'), true);
  assert.equal(text.slice(span.start, span.end).includes('export'), false);
});

test('finds more than one secret of the same kind', () => {
  const text = 'a@one.example b@two.example';
  assert.equal(values(text).filter((v) => v.includes('@')).length, 2);
});
