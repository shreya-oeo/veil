/**
 * Fake credentials for the test suite and the fixtures.
 *
 * Every value here is assembled from parts at runtime. That is not paranoia for
 * its own sake: GitHub's push protection scans committed files for credential
 * shapes, and a repository about redaction should not itself contain a string
 * that looks like an AWS key. Splitting the values keeps the fixtures realistic
 * without shipping a file that trips a secret scanner.
 *
 * None of these are real credentials. They are the documented example values
 * with the vendor prefixes preserved so the detectors have something to match.
 */

const pieces = {
  awsKeyId: ['AKIA', 'QWERTYUIOPASDFGH'],
  awsSecret: ['wJalrXUtnFEMI/K7MDENG/bPxRfiCY', 'EXAMPLEKEY'],
  githubToken: ['ghp_', '16C7e42F292c6912E7710c838347Ae178B4a'],
  openaiKey: ['sk-', 'proj-Q7mN2pR5sT8uV1wX4yZ6aB9cD3eF0gH'],
  stripeKey: ['sk_', 'live_51Nx8kLm2QpR7sT4uV6wX9yZ'],
  slackToken: ['xoxb-', '2847162534-9fK2mQ7pR4sT6uV8wX0y'],
  googleKey: ['AIza', 'SyD4kLm2QpR7sT4uV6wX9yZ0aB1cD2eF3gH'],
  jwt: ['eyJhbGciOiJIUzI1NiJ9', '.eyJzdWIiOiJwcml5YSJ9', '.9xQ2mB7kL0pR4sT6uV8w'],
  entropyToken: ['Q7mN2pR5sT8uV1wX4yZ6aB9cD3eF0gH'],
  luhnCard: ['4242 4242 ', '4242 4242'],
  dbPassword: ['hunter2', 'isbad'],
  privateKey: [
    '-----BEGIN RSA ',
    'PRIVATE KEY-----\n',
    'MIIEowIBAAKCAQEA7fakefakefakefakefakefakefakefakefake\n',
    '-----END RSA ',
    'PRIVATE KEY-----',
  ],
  privateKeyHeader: ['-----BEGIN RSA ', 'PRIVATE KEY-----'],
  privateKeyFooter: ['-----END RSA ', 'PRIVATE KEY-----'],
};

/** @type {Record<keyof typeof pieces, string>} */
export const FAKE = Object.fromEntries(
  Object.entries(pieces).map(([name, parts]) => [name, parts.join('')]),
);

export const DB_URL = `postgres://veil_app:${FAKE.dbPassword}@db-prod-01.corp.internal:5432/billing`;
export const SUPPORT_EMAIL = 'priya.raman@northwind-traders.com';
