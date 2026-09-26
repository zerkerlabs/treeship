import { createMDX } from 'fumadocs-mdx/next';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const withMDX = createMDX();
const docsRoot = dirname(fileURLToPath(import.meta.url));

const isDev = process.env.NODE_ENV === 'development';

// Content-Security-Policy. Mirrors the header set treeship.dev PR #121
// shipped for www (W2-7), narrowed to what this site actually loads:
// fonts are self-hosted static files (app/layout.tsx preloads
// /fonts/*.woff2), not Google Fonts, so there's no fonts.googleapis.com /
// fonts.gstatic.com exception here. Search is same-origin
// (fumadocs-core/search/server via /api/search), so 'self' covers it.
// There is no client-side WASM in this app (that's the main site's
// /verify page only), so no 'wasm-unsafe-eval'. script-src needs
// 'unsafe-inline': Next's App Router bootstraps with inline scripts, and
// the inline GA snippet in app/layout.tsx is one too; removing it means
// per-request nonces and dynamic rendering everywhere, a bigger change
// than this header pass.
const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline' https://www.googletagmanager.com${isDev ? " 'unsafe-eval'" : ''}`,
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data: https://www.googletagmanager.com https://*.google-analytics.com",
  `connect-src 'self' https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com${isDev ? ' ws:' : ''}`,
  "media-src 'self'",
  "manifest-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-src 'none'",
  "frame-ancestors 'none'",
  ...(isDev ? [] : ['upgrade-insecure-requests']),
].join('; ');

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  // Do not let an unrelated package-lock.json above the repository make Next
  // treat the user's entire home directory as this application's trace root.
  outputFileTracingRoot: docsRoot,
  allowedDevOrigins: ['localhost', '127.0.0.1'],
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'Content-Security-Policy', value: csp },
          { key: 'X-Frame-Options', value: 'DENY' },
          // No preload yet: submitting to the HSTS preload list is the owner's call.
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
        ],
      },
      {
        // The blog GIFs are up to 1.8 MB; Vercel revalidates public/ files on
        // every view by default.
        source: '/:path*.(gif|png|webp|jpg|jpeg|ico|svg|mp4)',
        headers: [{ key: 'Cache-Control', value: 'public, max-age=86400, stale-while-revalidate=604800' }],
      },
    ];
  },
  async redirects() {
    return [
      {
        source: '/docs/:path*',
        destination: '/:path*',
        permanent: true,
      },
      // Section-root redirects. Every section listed in
      // `docs/content/docs/meta.json` should resolve at its bare root URL --
      // a section that 404s when typed without the trailing page slug
      // looks broken to a human reader and (more importantly) to AI
      // agents/scrapers that treat /cli as canonical. The static
      // route-health check at scripts/check-docs-routes.py asserts each
      // entry below maps to a real first page.
      { source: '/cli',          destination: '/cli/overview',            permanent: false },
      { source: '/sdk',          destination: '/sdk/overview',            permanent: false },
      { source: '/api',          destination: '/api/overview',            permanent: false },
      { source: '/commerce',     destination: '/commerce/overview',       permanent: false },
      { source: '/reference',    destination: '/reference/schema',        permanent: false },
      { source: '/guides',       destination: '/guides/introduction',     permanent: false },
      { source: '/concepts',     destination: '/concepts/trust-fabric',   permanent: false },
      { source: '/integrations', destination: '/integrations/claude-code', permanent: false },
      { source: '/about',        destination: '/about/changelog',         permanent: false },
      // Friendly alias: the api/ section's title is "Hub API"; agents
      // crawling the sidebar often try /hub-api as the canonical URL.
      { source: '/hub-api',      destination: '/api/overview',            permanent: false },
      { source: '/cli/dock',     destination: '/cli/hub',                 permanent: true  },
    ];
  },
};

export default withMDX(config);
