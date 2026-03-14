# Modih Mail — Premium Disposable Email @modih.in

A cinematic, fully functional disposable email web app powered by Cloudflare Pages, Workers, D1, KV, and Email Routing.

## Features

- **Instant Disposable Email** — Generate random or custom `@modih.in` addresses
- **30-Minute Auto-Expiry** — Inboxes self-destruct after 30 minutes
- **Real Inbox** — Receive, read, and delete real emails
- **OTP Detection** — Automatically extracts verification codes
- **Cinematic UI** — Glassmorphism, video backgrounds, smooth animations
- **Fully Responsive** — Desktop video background, mobile image backgrounds
- **Rate Limiting** — IP-based via Cloudflare KV
- **Safe Rendering** — Sanitized HTML email display, no scripts/iframes

## Architecture

```
├── public/                 # Static frontend (Cloudflare Pages)
│   ├── index.html          # Main HTML
│   ├── styles.css          # Cinematic styles
│   ├── app.js              # Application logic
│   └── [media assets]      # Video/image backgrounds
├── functions/              # Cloudflare Pages Functions (API)
│   └── api/
│       ├── inbox.js        # POST/GET inbox endpoints
│       └── messages.js     # GET/DELETE messages endpoints
├── email-worker/           # Separate Email Worker for inbound mail
│   ├── index.js            # Email handler
│   ├── wrangler.toml       # Worker config
│   └── package.json        # Dependencies (postal-mime)
├── schema.sql              # D1 database schema
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
wrangler d1 execute modih-mail-db --file=schema.sql
```

### Step 4: Create KV Namespace

```bash
wrangler kv namespace create RATE_LIMIT
```

Copy the `id` from the output and update `wrangler.toml` → KV `id`.

### Step 5: Deploy Pages (Frontend + API)

```bash
npm install
wrangler pages project create modih-mail
wrangler pages deploy public --project-name=modih-mail
```

In the Cloudflare Dashboard, go to your Pages project → Settings → Functions → Bindings:
- Add **D1 Database** binding: Variable name `DB`, select `modih-mail-db`
- Add **KV Namespace** binding: Variable name `RATE_LIMIT`, select your KV namespace

### Step 6: Deploy Email Worker

```bash
cd email-worker
npm install
wrangler deploy
```

### Step 7: Configure Email Routing

1. Go to Cloudflare Dashboard → `modih.in` → Email → Email Routing
2. Enable Email Routing for your domain
3. Under **Routing Rules**, add a **Catch-all** rule:
   - Action: **Send to a Worker**
   - Destination: `modih-mail-email-worker`
4. This routes ALL `*@modih.in` emails to the worker

### Step 8: Custom Domain (Optional)

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
| POST | `/api/inbox` | Create inbox (`{ prefix?: string }`) |
| GET | `/api/inbox?email=x` | Get inbox info |
| GET | `/api/messages?inbox_id=x` | List messages |
| DELETE | `/api/messages?inbox_id=x` | Delete all messages |
| DELETE | `/api/messages?inbox_id=x&id=y` | Delete single message |

## License

Private project.
