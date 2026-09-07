import { blogSource } from '@/lib/blog';
import { notFound } from 'next/navigation';
import defaultMdxComponents from 'fumadocs-ui/mdx';
import Link from 'next/link';
import { BlogChrome } from '../chrome';

export default async function BlogPost(props: {
  params: Promise<{ slug: string[] }>;
}) {
  const { slug } = await props.params;
  const post = blogSource.getPage(slug);
  if (!post) notFound();

  const MDX = post.data.body;
  const tags: string[] = post.data.tags ?? [];
  const kicker = [post.data.date, ...tags].filter(Boolean).join(' · ');

  return (
    <>
      <BlogChrome crumb={post.data.title} />
      <main className="mx-auto w-full max-w-[860px] px-7 pb-20 pt-14">
        <p className="doc-kicker mb-3">{kicker}</p>
        <h1 className="mb-4 text-[clamp(30px,4vw,42px)] font-[750] leading-[1.08] tracking-[-0.03em] text-zk-ink [text-wrap:balance]">
          {post.data.title}
        </h1>
        {post.data.description && (
          <p className="doc-lede mb-2 max-w-[780px]">{post.data.description}</p>
        )}
        <div className="doc-meta mb-10 flex flex-wrap gap-x-6 gap-y-2 border-b border-zk-hairline pb-4 pt-4">
          {post.data.readTime && <span>{post.data.readTime}</span>}
          <Link href="/blog" className="text-zk-text-secondary no-underline hover:text-zk-accent">
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
    openGraph: {
      type: 'article',
      title: post.data.title,
      description: post.data.description,
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
