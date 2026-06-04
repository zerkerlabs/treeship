import { ImageResponse } from 'next/og';
import { blogSource } from '@/lib/blog';

export const alt = 'Treeship blog';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export function generateStaticParams() {
  return blogSource.getPages().map((page) => ({ slug: page.slugs }));
}

export default async function Image({
  params,
}: {
  params: Promise<{ slug: string[] }>;
}) {
  const { slug } = await params;
  const post = blogSource.getPage(slug);
  const title = post?.data.title ?? 'Treeship';

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
          padding: '72px 80px',
          fontFamily: 'sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
          <div
            style={{
              width: 16,
              height: 16,
              borderRadius: 5,
              background: '#4ade80',
            }}
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
            fontSize: 60,
            lineHeight: 1.12,
            color: '#ededed',
            fontWeight: 600,
            maxWidth: 1000,
          }}
        >
          {title}
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
