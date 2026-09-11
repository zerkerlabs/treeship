import { ImageResponse } from 'next/og';

export const runtime = 'edge';

function clamp(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1).trimEnd()}…`;
}

const GEIST_400 = 'https://fonts.gstatic.com/s/geist/v5/gyBhhwUxId8gMGYQMKR3pzfaWI_RnOM4nQ.ttf';
const GEIST_700 = 'https://fonts.gstatic.com/s/geist/v5/gyBhhwUxId8gMGYQMKR3pzfaWI_Re-Q4nQ.ttf';

async function loadFont(url: string): Promise<ArrayBuffer | null> {
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    return await res.arrayBuffer();
  } catch {
    return null;
  }
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const [regular, bold] = await Promise.all([loadFont(GEIST_400), loadFont(GEIST_700)]);
  const fonts = [
    regular ? { name: 'Geist', data: regular, weight: 400 as const, style: 'normal' as const } : null,
    bold ? { name: 'Geist', data: bold, weight: 700 as const, style: 'normal' as const } : null,
  ].filter(Boolean) as { name: string; data: ArrayBuffer; weight: 400 | 700; style: 'normal' }[];
  const family = fonts.length ? 'Geist' : 'sans-serif';
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
          background: '#f8f8f6',
          color: '#101010',
          padding: '64px 72px',
          fontFamily: family,
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
            <svg width="40" height="40" viewBox="0 0 26 26" fill="none">
              <circle cx="13" cy="5" r="3" fill="#0a0a0a" />
              <circle cx="5" cy="20" r="3" fill="#0a0a0a" fillOpacity="0.55" />
              <circle cx="21" cy="20" r="3" fill="#0a0a0a" fillOpacity="0.55" />
              <line x1="13" y1="8" x2="5" y2="17" stroke="#0a0a0a" strokeWidth="1.5" strokeOpacity="0.45" />
              <line x1="13" y1="8" x2="21" y2="17" stroke="#0a0a0a" strokeWidth="1.5" strokeOpacity="0.45" />
              <line x1="5" y1="20" x2="21" y2="20" stroke="#0a0a0a" strokeWidth="1" strokeOpacity="0.2" strokeDasharray="2 3" />
            </svg>
            <div
              style={{
                fontSize: 30,
                letterSpacing: -0.5,
                color: '#0a0a0a',
                fontWeight: 700,
              }}
            >
              Treeship
            </div>
          </div>
          <div
            style={{
              display: 'flex',
              fontSize: 20,
              letterSpacing: 3,
              textTransform: 'uppercase',
              color: '#5f6561',
              border: '1px solid #d9d9d4',
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
              color: '#5f6561',
              maxWidth: 1000,
            }}
          >
            {description}
          </div>
          <div style={{ display: 'flex', fontSize: 24, color: '#008503' }}>
            docs.treeship.dev
          </div>
        </div>
      </div>
    ),
    { width: 1200, height: 630, fonts },
  );
}
