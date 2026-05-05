# PayCycle API

Cloudflare Workers API built with `Hono` and `D1` for Google OAuth, recurring monthly commitments, and payment tracking.

## Features

- Google OAuth login for the mobile app
- JWT-based access and refresh token flow
- Cloudflare D1 storage for users, commitments, and payments
- Recurring monthly commitments that renew on the 1st day of each month
- OpenAPI JSON and Swagger UI endpoints

## Base URLs

- Production: `https://paycycle-api.traone.workers.dev`
- Local: `http://localhost:8787`

## Useful Endpoints

- `GET /`
- `GET /health`
- `GET /api-docs`
- `GET /api-json`

## Auth Flow

1. Mobile app opens `GET /auth/google`
2. API redirects to Google OAuth
3. Google redirects to `GET /auth/google/callback`
4. API issues app tokens and redirects back to the mobile deep link
5. Mobile app sends `Authorization: Bearer <access_token>` to protected routes

## Commitment Model

- Commitments are recurring monthly items
- Users do not provide a manual due date when creating a commitment
- The API treats each commitment as part of the current monthly cycle
- The cycle renews on the 1st day of every month
- Monthly payment progress is calculated per cycle

## Main Routes

### Auth

- `GET /auth/google`
- `GET /auth/google/callback`
- `POST /auth/refresh`
- `POST /auth/logout`

### Commitments

- `GET /commitments`
- `POST /commitments`
- `GET /commitments/:id`
- `PUT /commitments/:id`
- `DELETE /commitments/:id`

### Payments

- `GET /commitments/:id/payments`
- `POST /commitments/:id/payments`
- `GET /payments/:id`
- `PUT /payments/:id`
- `DELETE /payments/:id`

## Local Development

Install dependencies:

```bash
npm install
```

Apply local D1 migrations:

```bash
npm run d1:migrate:local
```

Start the Worker locally:

```bash
npm run dev
```

Open:

- `http://localhost:8787/api-docs`
- `http://localhost:8787/api-json`

## Environment

The Worker uses values from `wrangler.toml` and Cloudflare secrets. Typical values include:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `JWT_SECRET`
- `REFRESH_TOKEN_SECRET`

For production, keep secrets in Cloudflare Worker secrets rather than committing them.

## Database

Migrations live in:

```text
supabase/migrations/
```

Useful commands:

```bash
npm run d1:migrate:local
npm run d1:migrate:remote
```

## Scripts

- `npm run dev` starts local Wrangler development
- `npm run deploy` deploys the Worker
- `npm run build` runs TypeScript build
- `npm run lint` runs ESLint
- `npm run check` runs TypeScript type-checking
- `npm run d1:migrate:local` applies local D1 migrations
- `npm run d1:migrate:remote` applies remote D1 migrations

## Deploy

```bash
npm run deploy
```

## Notes

- Swagger UI is available at `/api-docs`
- OpenAPI JSON is available at `/api-json`
- The mobile app uses this API for browser-based Google login and commitment CRUD
