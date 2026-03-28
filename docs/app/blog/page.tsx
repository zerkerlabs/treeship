import Link from 'next/link';
import { blogSource } from '@/lib/blog';

export default function BlogIndex() {
  const posts = blogSource.getPages().sort((a, b) => {
    const da = a.data.date ?? '0';
    const db = b.data.date ?? '0';
    return db.localeCompare(da);
  });

  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="mb-2 text-3xl font-semibold tracking-tight">Blog</h1>
      <p className="mb-12 text-fd-muted-foreground">
        Technical deep dives from the Treeship team.
      </p>

      <div className="flex flex-col gap-8">
        {posts.map((post) => (
          <Link
            key={post.url}
            href={post.url}
            className="group block rounded-lg border border-fd-border p-5 transition-colors hover:border-fd-primary/40 hover:bg-fd-accent/50"
          >
            <time className="text-sm text-fd-muted-foreground">
              {post.data.date}
            </time>
            <h2 className="mt-1 text-lg font-medium group-hover:text-fd-primary">
              {post.data.title}
            </h2>
            <p className="mt-1.5 text-sm text-fd-muted-foreground line-clamp-2">
              {post.data.description}
            </p>
            {post.data.tags && post.data.tags.length > 0 && (
              <div className="mt-3 flex gap-2">
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
          </Link>
        ))}
      </div>
    </main>
  );
}
