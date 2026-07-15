import { ImageResponse } from 'next/og';

export const runtime = 'edge';

function clamp(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1).trimEnd()}…`;
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const title = clamp(url.searchParams.get('title') || 'Treeship Docs', 80);
  const description = clamp(
    url.searchParams.get('description') ||
      'Cryptographic receipts for AI agent actions. Verifiable proofs of what an agent did, when, and to which inputs.',
    145,
  );
  const section = clamp(url.searchParams.get('section') || 'docs', 28);

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
          color: '#ffffff',
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
              fontWeight: 700,
              letterSpacing: -1,
              maxWidth: 1040,
            }}
          >
            {title}
          </div>
          <div
            style={{
              display: 'flex',
              fontSize: 29,
              lineHeight: 1.4,
              color: '#d6dbd6',
              maxWidth: 1000,
            }}
          >
            {description}
          </div>
          <div style={{ display: 'flex', fontSize: 24, color: '#8aa090' }}>
            docs.treeship.dev
          </div>
        </div>
      </div>
    ),
    { width: 1200, height: 630 },
  );
}
