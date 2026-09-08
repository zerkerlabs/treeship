import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import type { ReactNode } from 'react';
import { source } from '@/lib/source';
import { CopyInstall } from '@/components/copy-install';
import { TreeshipMark } from '@/components/treeship-mark';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <DocsLayout
      tree={source.pageTree}
      nav={{
        title: (
          <span className="inline-flex items-center gap-2 text-base font-semibold tracking-tight text-fd-foreground">
            <TreeshipMark size={22} />
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
