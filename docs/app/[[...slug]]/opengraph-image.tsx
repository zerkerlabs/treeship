import { ImageResponse } from 'next/og';
import { source } from '@/lib/source';

// Per-page social card for every docs page. Next wires this into og:image and
// twitter:image (the root layout already sets metadataBase + summary_large_image).
// Previously docs pages shipped no image and inherited a generic "Treeship Docs"
// title, so every shared doc link looked identical. This shows the page's own
// title, a section label, and a snippet of its description for context.

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

  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          background: '#0a0f0a',
          backgroundImage:
            'radial-gradient(800px 460px at 88% -8%, rgba(74,222,128,0.16), transparent)',
          padding: '72px 80px',
          fontFamily: 'sans-serif',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
            <div
              style={{ width: 16, height: 16, borderRadius: 5, background: '#4ade80' }}
            />
            <div
              style={{
                fontSize: 28,
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
              fontSize: 22,
              letterSpacing: 3,
              textTransform: 'uppercase',
              color: '#6b7280',
              border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: 999,
              padding: '8px 18px',
            }}
          >
            {section}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div
            style={{
              display: 'flex',
              fontSize: 62,
              lineHeight: 1.08,
              color: '#ededed',
              fontWeight: 600,
              maxWidth: 1040,
            }}
          >
            {clamp(title, 80)}
          </div>
          <div
            style={{
              display: 'flex',
              fontSize: 30,
              lineHeight: 1.4,
              color: '#9ca3af',
              maxWidth: 1000,
            }}
          >
            {clamp(description, 150)}
          </div>
        </div>

        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderTop: '1px solid rgba(255,255,255,0.08)',
            paddingTop: 28,
          }}
        >
          <div style={{ fontSize: 26, color: '#999999' }}>docs.treeship.dev</div>
          <div style={{ fontSize: 22, color: '#666666' }}>
            Cryptographic receipts for AI agents
          </div>
        </div>
      </div>
    ),
    { ...size },
  );
}
