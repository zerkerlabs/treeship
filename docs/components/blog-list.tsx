import Link from 'next/link';
import { blogSource } from '@/lib/blog';
import {
  CATEGORIES,
  CATEGORY_ORDER,
  SYSTEMS,
  SYSTEM_GROUPS,
  systemInfo,
  tagSlug,
  type Category,
  type SystemGroup,
} from '@/lib/taxonomy';

// One listing for the whole blog: the index and every category, system and
// tag route render this with a different filter. Server component; the
// filters are links, so every view is a static page with its own URL.

export type Post = ReturnType<typeof blogSource.getPages>[number];

export interface Filter {
  category?: Category;
  system?: string;
  tag?: string;
}

export function allPosts(): Post[] {
  return blogSource.getPages().sort((a, b) => {
    const da = a.data.date ?? '0';
    const db = b.data.date ?? '0';
    return db.localeCompare(da);
  });
}

export function filterPosts(posts: Post[], filter: Filter): Post[] {
  return posts.filter((p) => {
    if (filter.category && p.data.category !== filter.category) return false;
    if (filter.system && !(p.data.systems ?? []).includes(filter.system)) return false;
    if (filter.tag && !(p.data.tags ?? []).some((t) => tagSlug(t) === filter.tag)) return false;
    return true;
  });
}

function count<K extends string>(posts: Post[], pick: (p: Post) => K[]): Map<K, number> {
  const m = new Map<K, number>();
  for (const p of posts) for (const k of pick(p)) m.set(k, (m.get(k) ?? 0) + 1);
  return m;
}

export function CategoryChip({ category, active }: { category: Category; active?: boolean }) {
  return (
    <Link
      href={`/blog/category/${category}`}
      className={
        active
          ? 'inline-flex items-center rounded-md bg-zk-ink px-2 py-0.5 font-mono text-[11px] text-white no-underline'
          : 'inline-flex items-center rounded-md bg-zk-accent-soft px-2 py-0.5 font-mono text-[11px] text-zk-accent no-underline hover:bg-zk-accent hover:text-white'
      }
    >
      {CATEGORIES[category].singular.toLowerCase()}
    </Link>
  );
}

export function SystemChip({ id, active }: { id: string; active?: boolean }) {
  const info = systemInfo(id);
  return (
    <Link
      href={`/blog/system/${id}`}
      className={
        active
          ? 'inline-flex items-center rounded-full border border-zk-ink bg-zk-ink px-2.5 py-0.5 text-[12px] font-medium text-white no-underline'
          : 'inline-flex items-center rounded-full border border-zk-hairline bg-zk-surface px-2.5 py-0.5 text-[12px] font-medium text-zk-text no-underline hover:border-zk-hairline-strong'
      }
    >
      {info.label}
    </Link>
  );
}

function FilterBar({ posts, filter }: { posts: Post[]; filter: Filter }) {
  const byCategory = count(posts, (p) => [p.data.category as Category]);
  const bySystem = count(posts, (p) => (p.data.systems ?? []) as string[]);
  const groups = new Map<SystemGroup, string[]>();
  for (const id of Object.keys(SYSTEMS)) {
    if (!bySystem.has(id)) continue;
    const g = SYSTEMS[id].group;
    groups.set(g, [...(groups.get(g) ?? []), id]);
  }
  const noFilter = !filter.category && !filter.system && !filter.tag;

  return (
    <nav aria-label="Filter posts" className="mb-10 flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-2">
        <Link
          href="/blog"
          className={
            noFilter
              ? 'rounded-full bg-zk-ink px-3.5 py-1.5 text-[13px] font-semibold text-white no-underline'
              : 'rounded-full border border-zk-hairline bg-zk-surface px-3.5 py-1.5 text-[13px] font-medium text-zk-text no-underline hover:border-zk-hairline-strong'
          }
        >
          All <span className="ml-1 font-mono text-[11px] opacity-60">{posts.length}</span>
        </Link>
        {CATEGORY_ORDER.filter((c) => byCategory.has(c)).map((c) => (
          <Link
            key={c}
            href={`/blog/category/${c}`}
            className={
              filter.category === c
                ? 'rounded-full bg-zk-ink px-3.5 py-1.5 text-[13px] font-semibold text-white no-underline'
                : 'rounded-full border border-zk-hairline bg-zk-surface px-3.5 py-1.5 text-[13px] font-medium text-zk-text no-underline hover:border-zk-hairline-strong'
            }
          >
            {CATEGORIES[c].label}{' '}
            <span className="ml-1 font-mono text-[11px] opacity-60">{byCategory.get(c)}</span>
          </Link>
        ))}
      </div>
      <div className="flex flex-col gap-3 border-t border-zk-hairline pt-5">
        {[...groups.entries()].map(([g, ids]) => (
          <div key={g} className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <span className="doc-meta w-full sm:w-[150px] sm:shrink-0">{SYSTEM_GROUPS[g]}</span>
            <div className="flex flex-wrap gap-1.5">
              {ids.map((id) => (
                <SystemChip key={id} id={id} active={filter.system === id} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </nav>
  );
}

function PostMeta({ post }: { post: Post }) {
  const systems = (post.data.systems ?? []) as string[];
  return (
    <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1.5">
      <time className="doc-meta">{post.data.date}</time>
      <CategoryChip category={post.data.category as Category} />
      {post.data.release && (
        <span className="doc-meta text-zk-ink">v{post.data.release}</span>
      )}
      {systems.map((id) => (
        <SystemChip key={id} id={id} />
      ))}
      {post.data.readTime && <span className="doc-meta">{post.data.readTime}</span>}
    </div>
  );
}

export function BlogList({
  filter,
  heading,
  lede,
}: {
  filter: Filter;
  heading: string;
  lede: string;
}) {
  const all = allPosts();
  const posts = filterPosts(all, filter);
  const [featured, ...rest] = filter.category || filter.system || filter.tag ? [undefined, ...posts] : posts;

  return (
    <main className="mx-auto w-full max-w-[860px] px-7 pb-20 pt-14">
      <p className="doc-kicker mb-3">Writing</p>
      <h1 className="mb-4 text-[clamp(30px,4vw,42px)] font-[750] leading-[1.08] tracking-[-0.03em] text-zk-ink [text-wrap:balance]">
        {heading}
      </h1>
      <p className="doc-lede mb-8 max-w-[780px]">{lede}</p>

      <FilterBar posts={all} filter={filter} />

      {featured && (
        <Link
          href={featured.url}
          className="group mb-8 block rounded-[14px] border border-zk-hairline bg-zk-surface p-6 no-underline transition-colors hover:border-zk-hairline-strong sm:p-8"
        >
          <span className="doc-meta text-zk-accent">Latest</span>
          <h2 className="mt-3 text-2xl font-bold leading-tight tracking-[-0.02em] text-zk-ink">
            {featured.data.title}
          </h2>
          <p className="mt-3 max-w-[780px] text-[15px] leading-relaxed text-zk-text-secondary">
            {featured.data.description}
          </p>
          <PostMeta post={featured} />
        </Link>
      )}

      {rest.length === 0 && !featured ? (
        <p className="doc-meta">Nothing here yet.</p>
      ) : (
        <div className="flex flex-col divide-y divide-zk-hairline rounded-[14px] border border-zk-hairline bg-zk-surface">
          {rest.filter(Boolean).map((post) => (
            <Link
              key={post!.url}
              href={post!.url}
              className="group block p-5 no-underline transition-colors hover:bg-zk-accent-soft first:rounded-t-[14px] last:rounded-b-[14px]"
            >
              <h2 className="text-[17px] font-semibold leading-snug tracking-[-0.01em] text-zk-ink">
                {post!.data.title}
              </h2>
              <p className="mt-1.5 line-clamp-2 text-[14px] leading-relaxed text-zk-text-secondary">
                {post!.data.description}
              </p>
              <PostMeta post={post!} />
            </Link>
          ))}
        </div>
      )}
    </main>
  );
}

/** Every value present on at least one post, for generateStaticParams. */
export function presentValues() {
  const posts = allPosts();
  const categories = new Set<string>();
  const systems = new Set<string>();
  const tags = new Set<string>();
  for (const p of posts) {
    categories.add(p.data.category as string);
    for (const s of (p.data.systems ?? []) as string[]) systems.add(s);
    for (const t of (p.data.tags ?? []) as string[]) tags.add(tagSlug(t));
  }
  return { categories: [...categories], systems: [...systems], tags: [...tags] };
}
