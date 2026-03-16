/**
 * Cloudflare Pages Middleware
 *
 * Intercepts the index.html response and injects:
 *   <script>window.TURNSTILE_SITE_KEY = "...";</script>
 *
 * This makes the server-side TURNSTILE_SITE_KEY env var available to
 * public/app.js without exposing it as a hardcoded client-side constant.
 *
 * Set the real value via:
 *   wrangler pages secret put TURNSTILE_SITE_KEY
 * or in the Cloudflare Dashboard → Pages → Settings → Environment variables.
 *
 * The wrangler.toml [vars] entry acts as a local-dev fallback only.
 */
export async function onRequest(context) {
  const { next, env, request } = context;

  const url = new URL(request.url);

  // Only transform the HTML document — pass everything else through
  if (!url.pathname.endsWith('/') && !url.pathname.endsWith('.html') && url.pathname !== '/') {
    return next();
  }

  const response = await next();

  // Only transform successful HTML responses
  const contentType = response.headers.get('content-type') || '';
  if (!response.ok || !contentType.includes('text/html')) {
    return response;
  }

  const siteKey = env.TURNSTILE_SITE_KEY || '';

  // Inject the site key script tag just before </head>
  const injectionScript = `<script>window.TURNSTILE_SITE_KEY = ${JSON.stringify(siteKey)};</script>`;

  // Create a new Headers object from the original, but remove Content-Length
  // as the transformation will change the body size.
  const newHeaders = new Headers(response.headers);
  newHeaders.delete('content-length');

  const html = await response.text();
  const transformed = html.replace('</head>', `${injectionScript}\n</head>`);

  return new Response(transformed, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}
