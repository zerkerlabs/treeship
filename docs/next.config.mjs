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
      { source: '/cli', destination: '/cli/overview', permanent: false },
      { source: '/sdk', destination: '/sdk/overview', permanent: false },
      { source: '/api', destination: '/api/overview', permanent: false },
      { source: '/commerce', destination: '/commerce/overview', permanent: false },
      { source: '/reference', destination: '/reference/schema', permanent: false },
      { source: '/cli/dock', destination: '/cli/hub', permanent: true },
    ];
  },
};

export default withMDX(config);
