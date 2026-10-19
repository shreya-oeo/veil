/**
 * Writes the fixture files. Run with `npm run fixtures`, or automatically
 * before `npm test`. Generated files are gitignored so the repository never
 * contains a credential-shaped literal.
 */

import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { FAKE, DB_URL, SUPPORT_EMAIL } from './fakes.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

const supportTicket = `# Billing migration — staging notes

Customer: Priya Raman at Northwind Traders.
Contact: ${SUPPORT_EMAIL} / +1 415 555 0132
Internal project: HALCYON-7
Staging host: billing-api.corp.internal
Database: db-prod-01.corp.internal:5432
Customer card on file: ${FAKE.luhnCard}

## Error

Checkout fails with \`ECONNRESET\` at 2026-10-17T09:14:22Z from 10.42.7.19.
Reproduced on staging only. Production at 54.203.18.7 is unaffected.

## Config used for the repro

\`\`\`ini
AWS_ACCESS_KEY_ID=${FAKE.awsKeyId}
AWS_SECRET_ACCESS_KEY=${FAKE.awsSecret}
DATABASE_URL=${DB_URL}
STRIPE_SECRET_KEY=${FAKE.stripeKey}
GITHUB_TOKEN=${FAKE.githubToken}
JWT_SIGNING_KEY=${FAKE.jwt}
SLACK_WEBHOOK_SECRET=${FAKE.slackToken}
GOOGLE_MAPS_KEY=${FAKE.googleKey}
\`\`\`

## Note

This ticket is under NDA with Northwind Traders. Do not forward it outside the
migration channel. The customer has not been told about the checkout failure yet.
`;

const sampleConfig = `# Example .env — every value below is fake, generated for the Veil test suite.
# Do not put real credentials in this file.

NODE_ENV=production
PORT=8080

AWS_ACCESS_KEY_ID=${FAKE.awsKeyId}
AWS_SECRET_ACCESS_KEY=${FAKE.awsSecret}
AWS_REGION=us-west-2

DATABASE_URL=${DB_URL}
REDIS_URL=redis://default:8f3a9c2e1b7d4f6a@cache-01.corp.internal:6379

GITHUB_TOKEN=${FAKE.githubToken}
OPENAI_API_KEY=${FAKE.openaiKey}
STRIPE_SECRET_KEY=${FAKE.stripeKey}
SLACK_BOT_TOKEN=${FAKE.slackToken}
GOOGLE_MAPS_KEY=${FAKE.googleKey}

# Placeholders should not be flagged.
API_TOKEN=<your-token-here>
SESSION_SECRET=changeme

INTERNAL_HOST=metrics.corp.internal
ADMIN_IP=10.42.7.19
`;

await writeFile(path.join(HERE, 'support-ticket.md'), supportTicket, 'utf8');
await writeFile(path.join(HERE, 'sample-config.txt'), sampleConfig, 'utf8');

process.stdout.write('Wrote fixtures/support-ticket.md and fixtures/sample-config.txt\n');
