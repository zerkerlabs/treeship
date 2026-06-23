import { source } from '@/lib/source';
import {
  DocsPage,
  DocsBody,
  DocsDescription,
  DocsTitle,
} from 'fumadocs-ui/page';
import { notFound, redirect } from 'next/navigation';
import defaultMdxComponents from 'fumadocs-ui/mdx';
import { LLMActions } from '@/components/llm-actions';
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
  if (!params.slug || params.slug.length === 0) {
    redirect('/guides/introduction');
  }
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
      <LLMActions url={page.url} />
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
  if (!params.slug || params.slug.length === 0) {
    return { title: 'Treeship Docs' };
  }
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const data = page.data as unknown as DocPageData;

  // Top-level title is the bare page title; the root layout's title.template
  // ("%s -- Treeship") adds the suffix. Returning the suffixed title here too
  // produced "Title -- Treeship -- Treeship". openGraph/twitter titles do not
  // inherit the template, so set the full title explicitly there.
  const fullTitle = `${data.title} -- Treeship`;
  const url = `/${(params.slug ?? []).join('/')}`;

  return {
    title: data.title,
    description: data.description,
    openGraph: {
      type: 'article',
      title: fullTitle,
      description: data.description,
      url,
    },
    twitter: {
      title: fullTitle,
      description: data.description,
    },
  };
}
