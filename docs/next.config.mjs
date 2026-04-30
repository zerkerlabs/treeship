import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
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
      // Friendly alias: the api/ section's title is "Hub API"; agents
      // crawling the sidebar often try /hub-api as the canonical URL.
      { source: '/hub-api',      destination: '/api/overview',            permanent: false },
      { source: '/cli/dock',     destination: '/cli/hub',                 permanent: true  },
    ];
  },
};

export default withMDX(config);
