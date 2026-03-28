import { blogSource } from '@/lib/blog';
import { notFound } from 'next/navigation';
import defaultMdxComponents from 'fumadocs-ui/mdx';
import Link from 'next/link';

export default async function BlogPost(props: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await props.params;
  const post = blogSource.getPage([slug]);
  if (!post) notFound();

  const MDX = post.data.body;

  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <Link
        href="/blog"
        className="mb-8 inline-block text-sm text-fd-muted-foreground hover:text-fd-primary"
      >
        &larr; Back to blog
      </Link>

      <header className="mb-10">
        <time className="text-sm text-fd-muted-foreground">
          {post.data.date}
        </time>
        {post.data.readTime && (
          <span className="ml-3 text-sm text-fd-muted-foreground">
            {post.data.readTime}
          </span>
        )}
        <h1 className="mt-2 text-3xl font-semibold tracking-tight">
          {post.data.title}
        </h1>
        <p className="mt-2 text-fd-muted-foreground">
          {post.data.description}
        </p>
        {post.data.tags && post.data.tags.length > 0 && (
          <div className="mt-4 flex gap-2">
            {post.data.tags.map((tag: string) => (
              <span
                key={tag}
                className="rounded-full bg-fd-accent px-2.5 py-0.5 text-xs text-fd-muted-foreground"
              >
                {tag}
              </span>
            ))}
          </div>
        )}
      </header>

      <article className="prose dark:prose-invert">
        <MDX components={{ ...defaultMdxComponents }} />
      </article>
    </main>
  );
}

export function generateStaticParams() {
  return blogSource.getPages().map((page) => ({
    slug: page.slugs[0],
  }));
}

export function generateMetadata(props: {
  params: Promise<{ slug: string }>;
}) {
  return props.params.then(({ slug }) => {
    const post = blogSource.getPage([slug]);
    if (!post) return {};
    return {
      title: post.data.title,
      description: post.data.description,
    };
  });
}
