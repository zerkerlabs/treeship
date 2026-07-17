import './global.css';
import { RootProvider } from 'fumadocs-ui/provider';
import Script from 'next/script';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';

const siteUrl = 'https://docs.treeship.dev';
const siteName = 'Treeship';
const siteDescription =
  'Cryptographic receipts for AI agent actions. Verifiable proofs of what an agent did, when, and to which inputs.';

export const metadata: Metadata = {
  metadataBase: new URL('https://docs.treeship.dev'),
  title: {
    default: 'Treeship Docs',
    template: '%s -- Treeship',
  },
  description: siteDescription,
  applicationName: siteName,
  openGraph: {
    type: 'website',
    siteName,
    title: 'Treeship Docs',
    description: siteDescription,
    url: siteUrl,
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Treeship Docs',
    description: siteDescription,
  },
};

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500&family=Geist+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <RootProvider>{children}</RootProvider>
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
