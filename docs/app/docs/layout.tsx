import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import type { ReactNode } from 'react';
import { source } from '@/lib/source';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <DocsLayout
      tree={source.pageTree}
      nav={{
        title: (
          <span style={{ fontFamily: 'Georgia, serif', fontSize: '20px', color: '#3ECF6E' }}>
            Treeship
          </span>
        ),
        url: '/',
        children: (
          <>
            <a
              href="https://github.com/zerkerlabs/treeship"
              target="_blank"
              rel="noopener noreferrer"
              style={{ fontSize: '13px', color: '#8FA88F' }}
            >
              GitHub
            </a>
            <a
              href="https://treeship.dev"
              target="_blank"
              rel="noopener noreferrer"
              style={{ fontSize: '13px', color: '#8FA88F' }}
            >
              treeship.dev
            </a>
          </>
        ),
      }}
      sidebar={{
        banner: (
          <div style={{
            background: 'rgba(62,207,110,0.08)',
            border: '0.5px solid rgba(62,207,110,0.2)',
            borderRadius: '7px',
            padding: '10px 12px',
            fontSize: '12px',
            color: '#8FA88F',
            fontFamily: 'monospace',
          }}>
            cargo install treeship
          </div>
        ),
      }}
    >
      {children}
    </DocsLayout>
  );
}
