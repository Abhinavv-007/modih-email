# Modih Mail — Premium Disposable Email @modih.in

A cinematic, fully functional disposable email web app powered by Cloudflare Pages, Workers, D1, KV, and Email Routing.

## Features

- **Instant Disposable Email** — Generate random `@modih.in` addresses (custom prefixes with Pro)
- **3-Hour Auto-Expiry** — Free inboxes self-destruct after 3 hours (Pro: 7 days)
- **Real Inbox** — Receive, read, and delete real emails
- **OTP Detection** — Automatically extracts verification codes
- **Cinematic UI** — Glassmorphism, video backgrounds, smooth animations
- **Fully Responsive** — Desktop video background, mobile image backgrounds
- **Abuse Prevention** — IP + browser token tracking, Cloudflare Turnstile CAPTCHA
- **Rate Limiting** — IP-based via Cloudflare KV + D1 visitor tracking
- **Safe Rendering** — Sanitized HTML email display, no scripts/iframes

## Free-Tier Limits

| Limit | Value |
|-------|-------|
| Inbox creations per 24h | 3 |
| Active inboxes | 1 |
| Inbox retention | 3 hours |
| Custom prefix | ❌ (Pro only) |
| Turnstile CAPTCHA | After 2nd creation |
| Hard block | After 3rd creation, resets after 24h |

## Architecture

```
├── public/                 # Static frontend (Cloudflare Pages)
│   ├── index.html          # Main HTML (hero, features, pricing, generate)
│   ├── styles.css          # Cinematic styles + pricing section
│   ├── app.js              # Application logic + pricing toggle
│   └── [media assets]      # Video/image backgrounds
├── functions/              # Cloudflare Pages Functions (API)
│   └── api/
│       ├── inbox.js        # POST/DELETE inbox + abuse prevention
│       └── messages.js     # GET/DELETE messages endpoints
├── email-worker/           # Separate Email Worker for inbound mail
│   ├── index.js            # Email handler
│   ├── wrangler.toml       # Worker config
│   └── package.json        # Dependencies (postal-mime)
├── final-desptop-tab.sql   # D1 database schema
├── migrate-free-tier.sql   # Visitor tracking migration
├── wrangler.toml           # Pages project config
└── package.json            # Project dependencies
```

## Deployment Guide

### Prerequisites

- Cloudflare account with a domain (`modih.in`) added
- Node.js 18+ installed
- Wrangler CLI: `npm install -g wrangler`

### Step 1: Authenticate with Cloudflare

```bash
wrangler login
```

### Step 2: Create D1 Database

```bash
wrangler d1 create modih-mail-db
```

Copy the `database_id` from the output and update it in:
- `wrangler.toml` → `database_id`
- `email-worker/wrangler.toml` → `database_id`

### Step 3: Initialize D1 Schema

```bash
wrangler d1 execute modih-mail-db --file=final-desptop-tab.sql
```

### Step 4: Run Free-Tier Migration

```bash
npm run db:migrate:free-tier
```

This creates the `visitor_actions` table for tracking inbox creation per visitor.

### Step 5: Create KV Namespace

```bash
wrangler kv namespace create RATE_LIMIT
```

Copy the `id` from the output and update `wrangler.toml` → KV `id`.

### Step 6: Set Up Cloudflare Turnstile

1. Go to [Cloudflare Dashboard → Turnstile](https://dash.cloudflare.com/?to=/:account/turnstile)
2. Create a new Turnstile widget for your domain
3. Copy the **Site Key** and update `wrangler.toml` → `TURNSTILE_SITE_KEY`
4. Set the **Secret Key** as a secret:

```bash
wrangler secret put TURNSTILE_SECRET
```

### Step 7: Deploy Pages (Frontend + API)

```bash
npm install
wrangler pages project create modih-mail
wrangler pages deploy public --project-name=modih-mail
```

In the Cloudflare Dashboard, go to your Pages project → Settings → Functions → Bindings:
- Add **D1 Database** binding: Variable name `DB`, select `modih-mail-db`
- Add **KV Namespace** binding: Variable name `RATE_LIMIT`, select your KV namespace

### Step 8: Deploy Email Worker

```bash
cd email-worker
npm install
wrangler deploy
```

### Step 9: Configure Email Routing

1. Go to Cloudflare Dashboard → `modih.in` → Email → Email Routing
2. Enable Email Routing for your domain
3. Under **Routing Rules**, add a **Catch-all** rule:
   - Action: **Send to a Worker**
   - Destination: `modih-mail-email-worker`
4. This routes ALL `*@modih.in` emails to the worker

### Step 10: Custom Domain (Optional)

In Pages project settings, add a custom domain (e.g., `mail.modih.in`).

## Local Development

```bash
npm install
npm run dev
```

This starts a local dev server at `http://localhost:8788` with D1 and KV bindings.

> **Note:** Email receiving only works in production with Cloudflare Email Routing.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/inbox` | Create inbox (random only for free; sends `X-Browser-Token`) |
| DELETE | `/api/inbox?id=x` | Delete inbox (requires `X-Owner-Token`) |
| GET | `/api/messages?inbox_id=x` | List messages (requires `X-Owner-Token`) |
| DELETE | `/api/messages?inbox_id=x` | Delete all messages |
| DELETE | `/api/messages?inbox_id=x&id=y` | Delete single message |

## Plans

| Plan | Price | Highlights |
|------|-------|------------|
| Guest | Free | 3 inboxes/day, 1 active, 3h retention, random only |
| Pro | $6/mo | Custom prefix, 10 active, 7-day retention, no captcha |
| Developer | $29/mo | API keys, webhooks, 5k creates/mo, IP allowlist |

## License

Private project.
