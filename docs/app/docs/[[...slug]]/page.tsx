import { source } from '@/lib/source';
import {
  DocsPage,
  DocsBody,
  DocsDescription,
  DocsTitle,
} from 'fumadocs-ui/page';
import { notFound } from 'next/navigation';
import defaultMdxComponents from 'fumadocs-ui/mdx';
import type { FC } from 'react';
import type { MDXProps } from 'mdx/types';
import type { TableOfContents } from 'fumadocs-core/server';

interface DocPageData {
  title: string;
  description?: string;
  full?: boolean;
  body: FC<MDXProps>;
  toc: TableOfContents;
}

export default async function Page(props: {
  params: Promise<{ slug?: string[] }>;
}) {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const data = page.data as unknown as DocPageData;
  const MDX = data.body;

  return (
    <DocsPage
      toc={data.toc}
      full={data.full}
      editOnGithub={{
        owner: 'zerkerlabs',
        repo: 'treeship',
        sha: 'main',
        path: `docs/content/docs/${page.path}`,
      }}
    >
      <DocsTitle>{data.title}</DocsTitle>
      <DocsDescription>{data.description}</DocsDescription>
      <DocsBody>
        <MDX components={{ ...defaultMdxComponents }} />
      </DocsBody>
    </DocsPage>
  );
}

export async function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata(props: {
  params: Promise<{ slug?: string[] }>;
}) {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const data = page.data as unknown as DocPageData;

  return {
    title: `${data.title} -- Treeship`,
    description: data.description,
  };
}
