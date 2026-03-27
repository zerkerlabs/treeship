import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import type { ReactNode } from 'react';
import { source } from '@/lib/source';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <DocsLayout
      tree={source.pageTree}
      nav={{
        title: (
          <span className="font-serif text-xl text-fd-primary">
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
              className="text-xs text-fd-muted-foreground hover:text-fd-primary transition-colors"
            >
              GitHub
            </a>
            <a
              href="https://treeship.dev"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-fd-muted-foreground hover:text-fd-primary transition-colors"
            >
              treeship.dev
            </a>
          </>
        ),
      }}
      sidebar={{
        banner: (
          <div className="sidebar-install-banner rounded-lg px-3 py-2.5 text-xs font-mono text-fd-muted-foreground">
            cargo install treeship
          </div>
        ),
      }}
    >
      {children}
    </DocsLayout>
  );
}
