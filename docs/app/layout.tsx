import './global.css';
import { RootProvider } from 'fumadocs-ui/provider';
import Script from 'next/script';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';

const siteUrl = 'https://docs.treeship.dev';
const siteName = 'Treeship';
const siteDescription =
  'Cryptographic receipts for AI agent actions. Verifiable proofs of what an agent did, when, and to which inputs.';

const defaultImage = `/og?${new URLSearchParams({
  title: 'Treeship Docs',
  description: siteDescription,
  section: 'docs',
}).toString()}`;

export const metadata: Metadata = {
  metadataBase: new URL('https://docs.treeship.dev'),
  title: {
    default: 'Treeship Docs',
    template: '%s -- Treeship',
  },
  description: siteDescription,
  applicationName: siteName,
  alternates: { canonical: siteUrl },
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true, 'max-image-preview': 'large', 'max-snippet': -1 },
  },
  openGraph: {
    type: 'website',
    siteName,
    locale: 'en_US',
    title: 'Treeship Docs',
    description: siteDescription,
    url: siteUrl,
    // Every page without its own image (the blog index, the root) still
    // shares with the Treeship card rather than whatever a crawler picks.
    images: [{ url: defaultImage, width: 1200, height: 630, alt: 'Treeship Docs' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Treeship Docs',
    description: siteDescription,
    images: [defaultImage],
  },
};

// Structured data for search: who publishes this, what it documents.
const structuredData = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'Organization',
      '@id': 'https://zerkerlabs.com/#org',
      name: 'Zerker Labs',
      url: 'https://zerkerlabs.com',
      logo: 'https://www.treeship.dev/icon-512.png',
      sameAs: ['https://github.com/zerkerlabs', 'https://moltbook.com/u/treeshipzk'],
    },
    {
      '@type': 'WebSite',
      '@id': `${siteUrl}/#website`,
      url: siteUrl,
      name: 'Treeship Docs',
      publisher: { '@id': 'https://zerkerlabs.com/#org' },
      about: { '@id': 'https://www.treeship.dev/#software' },
    },
  ],
};

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700;800&family=Geist+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
        />
        <RootProvider theme={{ defaultTheme: 'light' }}>{children}</RootProvider>
        <Script
          src="https://www.googletagmanager.com/gtag/js?id=G-SHQD226S2V"
          strategy="afterInteractive"
        />
        <Script id="google-analytics" strategy="afterInteractive">
          {`
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
            gtag('config', 'G-SHQD226S2V');
          `}
        </Script>
      </body>
    </html>
  );
}
