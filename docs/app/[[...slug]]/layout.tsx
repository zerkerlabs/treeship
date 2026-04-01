import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import type { ReactNode } from 'react';
import { source } from '@/lib/source';
import { CopyInstall } from '@/components/copy-install';

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
      }}
      links={[
        {
          text: 'Blog',
          url: '/blog',
        },
        {
          text: 'GitHub',
          url: 'https://github.com/zerkerlabs/treeship',
          external: true,
        },
        {
          text: 'treeship.dev',
          url: 'https://treeship.dev',
          external: true,
        },
      ]}
      sidebar={{
        banner: <CopyInstall />,
      }}
    >
      {children}
    </DocsLayout>
  );
}
