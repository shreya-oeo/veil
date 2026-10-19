# Billing migration — staging notes

Customer: Priya Raman at Northwind Traders.
Contact: priya.raman@northwind-traders.com / +1 415 555 0132
Internal project: HALCYON-7
Staging host: billing-api.corp.internal
Database: db-prod-01.corp.internal:5432
Customer card on file: 4242 4242 4242 4242

## Error

Checkout fails with `ECONNRESET` at 2026-10-17T09:14:22Z from 10.42.7.19.
Reproduced on staging only. Production at 54.203.18.7 is unaffected.

## Config used for the repro

```ini
AWS_ACCESS_KEY_ID=AKIAQWERTYUIOPASDFGH
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgres://veil_app:hunter2isbad@db-prod-01.corp.internal:5432/billing
STRIPE_SECRET_KEY=sk_live_51Nx8kLm2QpR7sT4uV6wX9yZ
GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a
JWT_SIGNING_KEY=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcml5YSJ9.9xQ2mB7kL0pR4sT6uV8w
SLACK_WEBHOOK_SECRET=xoxb-2847162534-9fK2mQ7pR4sT6uV8wX0y
GOOGLE_MAPS_KEY=AIzaSyD4kLm2QpR7sT4uV6wX9yZ0aB1cD2eF3gH
```

## Note

This ticket is under NDA with Northwind Traders. Do not forward it outside the
migration channel. The customer has not been told about the checkout failure yet.
