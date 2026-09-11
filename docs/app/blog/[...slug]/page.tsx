import { blogSource } from '@/lib/blog';
import { notFound } from 'next/navigation';
import defaultMdxComponents from 'fumadocs-ui/mdx';
import Link from 'next/link';
import { BlogChrome } from '../chrome';
import { CategoryChip, SystemChip } from '@/components/blog-list';
import { CATEGORIES, tagSlug, type Category } from '@/lib/taxonomy';

export default async function BlogPost(props: {
  params: Promise<{ slug: string[] }>;
}) {
  const { slug } = await props.params;
  const post = blogSource.getPage(slug);
  if (!post) notFound();

  const MDX = post.data.body;
  const tags: string[] = post.data.tags ?? [];
  const systems: string[] = post.data.systems ?? [];
  const category = post.data.category as Category;
  const kicker = [
    CATEGORIES[category].singular,
    post.data.release ? `v${post.data.release}` : undefined,
    post.data.date,
  ]
    .filter(Boolean)
    .join(' · ');
  const image = `https://docs.treeship.dev/og?${new URLSearchParams({
    title: post.data.title,
    description: post.data.description ?? '',
    section: 'blog',
  }).toString()}`;
  const structuredData = {
    '@context': 'https://schema.org',
    '@type': 'BlogPosting',
    headline: post.data.title,
    description: post.data.description ?? '',
    datePublished: post.data.date ? `${post.data.date}T00:00:00Z` : undefined,
    image,
    keywords: [...tags, ...systems].join(', ') || undefined,
    articleSection: CATEGORIES[category].label,
    mainEntityOfPage: `https://docs.treeship.dev${post.url}`,
    author: { '@type': 'Organization', name: 'Zerker Labs', url: 'https://zerkerlabs.com' },
    publisher: {
      '@type': 'Organization',
      name: 'Zerker Labs',
      url: 'https://zerkerlabs.com',
      logo: { '@type': 'ImageObject', url: 'https://www.treeship.dev/icon-512.png' },
    },
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
      />
      <BlogChrome crumb={post.data.title} />
      <main className="mx-auto w-full max-w-[860px] px-7 pb-20 pt-14">
        <p className="doc-kicker mb-3">{kicker}</p>
        <h1 className="mb-4 text-[clamp(30px,4vw,42px)] font-[750] leading-[1.08] tracking-[-0.03em] text-zk-ink [text-wrap:balance]">
          {post.data.title}
        </h1>
        {post.data.description && (
          <p className="doc-lede mb-2 max-w-[780px]">{post.data.description}</p>
        )}
        <div className="mb-10 flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-zk-hairline pb-4 pt-4">
          <CategoryChip category={category} />
          {systems.map((id) => (
            <SystemChip key={id} id={id} />
          ))}
          {tags.map((t) => (
            <Link
              key={t}
              href={`/blog/tag/${tagSlug(t)}`}
              className="doc-meta no-underline hover:text-zk-accent"
            >
              #{tagSlug(t)}
            </Link>
          ))}
          {post.data.readTime && <span className="doc-meta">{post.data.readTime}</span>}
          {post.data.written && (
            <span className="doc-meta" title="A retrospective entry, filed under the date of the release it documents.">
              written {post.data.written}
            </span>
          )}
          <Link href="/blog" className="doc-meta ml-auto text-zk-text-secondary no-underline hover:text-zk-accent">
            All posts
          </Link>
        </div>

        <article className="prose blog-prose max-w-none">
          <MDX components={{ ...defaultMdxComponents }} />
        </article>
      </main>
    </>
  );
}

export function generateStaticParams() {
  return blogSource.getPages().map((page) => ({
    slug: page.slugs,
  }));
}

export async function generateMetadata(props: {
  params: Promise<{ slug: string[] }>;
}) {
  const { slug } = await props.params;
  const post = blogSource.getPage(slug);
  if (!post) return {};
  const image = `/og?${new URLSearchParams({
    title: post.data.title,
    description: post.data.description ?? '',
    section: 'blog',
  }).toString()}`;
  return {
    title: post.data.title,
    description: post.data.description,
    alternates: { canonical: post.url },
    openGraph: {
      type: 'article',
      title: post.data.title,
      description: post.data.description,
      url: post.url,
      siteName: 'Treeship',
      publishedTime: post.data.date ? `${post.data.date}T00:00:00Z` : undefined,
      authors: ['Zerker Labs'],
      tags: post.data.tags ?? [],
      images: [{ url: image, width: 1200, height: 630, alt: post.data.title }],
    },
    twitter: {
      card: 'summary_large_image',
      title: post.data.title,
      description: post.data.description,
      images: [image],
    },
  };
}
