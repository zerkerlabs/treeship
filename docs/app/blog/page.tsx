import Link from 'next/link';
import { blogSource } from '@/lib/blog';
import { BlogChrome } from './chrome';

const indexImage = `/og?${new URLSearchParams({
  title: 'Treeship blog',
  description: 'Agent trust, portable verification, and cryptographic accountability in AI workflows.',
  section: 'blog',
}).toString()}`;

export const metadata = {
  title: 'Blog',
  description: 'Agent trust, portable verification, and cryptographic accountability in AI workflows.',
  alternates: { canonical: '/blog' },
  openGraph: {
    title: 'Treeship blog',
    description: 'Agent trust, portable verification, and cryptographic accountability in AI workflows.',
    url: '/blog',
    images: [{ url: indexImage, width: 1200, height: 630, alt: 'Treeship blog' }],
  },
  twitter: { card: 'summary_large_image', title: 'Treeship blog', images: [indexImage] },
};

export default function BlogIndex() {
  const posts = blogSource.getPages().sort((a, b) => {
    const da = a.data.date ?? '0';
    const db = b.data.date ?? '0';
    return db.localeCompare(da);
  });

  const featured = posts[0];
  const rest = posts.slice(1);

  return (
    <>
      <BlogChrome crumb="Writing" />
      <main className="mx-auto w-full max-w-[860px] px-7 pb-20 pt-14">
        <p className="doc-kicker mb-3">Writing</p>
        <h1 className="mb-4 text-[clamp(30px,4vw,42px)] font-[750] leading-[1.08] tracking-[-0.03em] text-zk-ink">
          Blog
        </h1>
        <p className="doc-lede mb-10 max-w-[780px]">
          Agent trust, portable verification, and cryptographic accountability in AI workflows.
        </p>

        {featured && (
          <Link
            href={featured.url}
            className="group mb-8 block rounded-[14px] border border-zk-hairline bg-zk-surface p-6 no-underline transition-colors hover:border-zk-hairline-strong sm:p-8"
          >
            <span className="doc-meta text-zk-accent">Latest · {featured.data.date}</span>
            <h2 className="mt-3 text-2xl font-bold leading-tight tracking-[-0.02em] text-zk-ink">
              {featured.data.title}
            </h2>
            <p className="mt-3 max-w-[780px] text-[15px] leading-relaxed text-zk-text-secondary">
              {featured.data.description}
            </p>
            {featured.data.readTime && (
              <span className="doc-meta mt-4 block">{featured.data.readTime}</span>
            )}
          </Link>
        )}

        <div className="flex flex-col divide-y divide-zk-hairline rounded-[14px] border border-zk-hairline bg-zk-surface">
          {rest.map((post) => (
            <Link
              key={post.url}
              href={post.url}
              className="group block p-5 no-underline transition-colors hover:bg-zk-accent-soft first:rounded-t-[14px] last:rounded-b-[14px]"
            >
              <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
                <div className="flex-1">
                  <h2 className="text-[17px] font-semibold leading-snug tracking-[-0.01em] text-zk-ink">
                    {post.data.title}
                  </h2>
                  <p className="mt-1.5 line-clamp-2 text-[14px] leading-relaxed text-zk-text-secondary">
                    {post.data.description}
                  </p>
                </div>
                <time className="doc-meta shrink-0 sm:mt-1">{post.data.date}</time>
              </div>
            </Link>
          ))}
        </div>
      </main>
    </>
  );
}
