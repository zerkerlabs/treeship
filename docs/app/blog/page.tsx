import Link from 'next/link';
import { blogSource } from '@/lib/blog';

export default function BlogIndex() {
  const posts = blogSource.getPages().sort((a, b) => {
    const da = a.data.date ?? '0';
    const db = b.data.date ?? '0';
    return db.localeCompare(da);
  });

  const featured = posts[0];
  const rest = posts.slice(1);

  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="mb-2 text-3xl font-semibold tracking-tight">Blog</h1>
      <p className="mb-12 text-fd-muted-foreground">
        Thinking about agent trust, portable verification, and cryptographic accountability in AI workflows.
      </p>

      {/* Featured / Latest */}
      {featured && (
        <Link
          href={featured.url}
          className="group mb-10 block rounded-xl border border-fd-border p-6 sm:p-8 transition-colors hover:border-fd-primary/40 hover:bg-fd-accent/50"
        >
          <span className="text-xs font-medium uppercase tracking-wider text-fd-primary">
            Latest
          </span>
          <h2 className="mt-3 text-2xl font-semibold tracking-tight group-hover:text-fd-primary">
            {featured.data.title}
          </h2>
          <p className="mt-3 text-sm leading-relaxed text-fd-muted-foreground">
            {featured.data.description}
          </p>
          <time className="mt-4 block text-xs text-fd-muted-foreground font-mono">
            {featured.data.date}
          </time>
        </Link>
      )}

      {/* Rest */}
      <div className="flex flex-col gap-4">
        {rest.map((post) => (
          <Link
            key={post.url}
            href={post.url}
            className="group block rounded-lg border border-fd-border p-5 transition-colors hover:border-fd-primary/40 hover:bg-fd-accent/50"
          >
            <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1 sm:gap-6">
              <div className="flex-1">
                <h2 className="text-base font-medium group-hover:text-fd-primary">
                  {post.data.title}
                </h2>
                <p className="mt-1.5 text-sm text-fd-muted-foreground line-clamp-2">
                  {post.data.description}
                </p>
              </div>
              <time className="shrink-0 text-xs text-fd-muted-foreground font-mono sm:mt-1">
                {post.data.date}
              </time>
            </div>
          </Link>
        ))}
      </div>
    </main>
  );
}
