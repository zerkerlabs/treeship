import { ImageResponse } from 'next/og';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { source } from '@/lib/source';

// Per-page social card for every docs page, composed over the hero painting.
// Next wires this into og:image and twitter:image (the root layout already
// sets metadataBase + summary_large_image). Shows the page's own title, a
// section label, and a snippet of its description for context, over a darkened
// crop of the homepage hero so docs links share with visual identity.

export const alt = 'Treeship docs';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export function generateStaticParams() {
  return source.getPages().map((page) => ({ slug: page.slugs }));
}

function clamp(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max - 1).trimEnd() + '…';
}

export default async function Image({
  params,
}: {
  params: Promise<{ slug?: string[] }>;
}) {
  const { slug } = await params;
  const page = slug && slug.length > 0 ? source.getPage(slug) : undefined;

  const title = page?.data.title ?? 'Treeship Docs';
  const description =
    page?.data.description ??
    'Cryptographic receipts for AI agent actions. Verifiable proofs of what an agent did, when, and to which inputs.';
  const section = (slug && slug.length > 0 ? slug[0] : 'docs').replace(/-/g, ' ');

  const bg = readFileSync(join(process.cwd(), 'public', 'hero-bg.png'));
  const bgUri = `data:image/png;base64,${bg.toString('base64')}`;

  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          position: 'relative',
          background: '#0a0f0a',
        }}
      >
        {/* hero painting, full bleed */}
        <img
          src={bgUri}
          width={1200}
          height={630}
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: 1200,
            height: 630,
            objectFit: 'cover',
            objectPosition: 'center',
          }}
        />

        {/* heavy scrim: text-dense card needs strong legibility */}
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: 1200,
            height: 630,
            display: 'flex',
            background:
              'linear-gradient(180deg, rgba(7,11,7,0.55) 0%, rgba(7,11,7,0.72) 40%, rgba(7,11,7,0.95) 100%)',
          }}
        />

        {/* content */}
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: 1200,
            height: 630,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            padding: '64px 72px',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div
                style={{ width: 16, height: 16, borderRadius: 5, background: '#4ade80' }}
              />
              <div
                style={{
                  fontSize: 26,
                  letterSpacing: 6,
                  color: '#4ade80',
                  fontWeight: 600,
                }}
              >
                TREESHIP
              </div>
            </div>
            <div
              style={{
                display: 'flex',
                fontSize: 20,
                letterSpacing: 3,
                textTransform: 'uppercase',
                color: '#cbd5cf',
                background: 'rgba(0,0,0,0.35)',
                border: '1px solid rgba(255,255,255,0.18)',
                borderRadius: 999,
                padding: '8px 18px',
              }}
            >
              {section}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
            <div
              style={{
                display: 'flex',
                fontSize: 60,
                lineHeight: 1.08,
                color: '#ffffff',
                fontWeight: 700,
                letterSpacing: -1,
                maxWidth: 1040,
                textShadow: '0 2px 24px rgba(0,0,0,0.6)',
              }}
            >
              {clamp(title, 80)}
            </div>
            <div
              style={{
                display: 'flex',
                fontSize: 29,
                lineHeight: 1.4,
                color: '#d6dbd6',
                maxWidth: 1000,
                textShadow: '0 1px 16px rgba(0,0,0,0.6)',
              }}
            >
              {clamp(description, 145)}
            </div>
            <div
              style={{
                display: 'flex',
                fontSize: 24,
                color: '#8aa090',
                marginTop: 4,
              }}
            >
              docs.treeship.dev
            </div>
          </div>
        </div>
      </div>
    ),
    { ...size },
  );
}
