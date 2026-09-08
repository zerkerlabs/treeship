import Link from 'next/link';
import { TreeshipWordmark } from '@/components/treeship-mark';

// The sticky document chrome from the design system: wordmark, a crumb, and
// the two places a reader of a post goes next. Server component; no state.
export function BlogChrome({ crumb }: { crumb: string }) {
  return (
    <div className="sticky top-0 z-10 flex items-center gap-4 border-b border-zk-hairline bg-zk-bg/90 px-7 py-3.5 font-mono text-[11px] uppercase tracking-[0.12em] text-zk-text-secondary backdrop-blur">
      <Link href="https://treeship.dev" className="no-underline" aria-label="Treeship home">
        <TreeshipWordmark />
      </Link>
      <span className="flex-1 truncate">{crumb}</span>
      <Link href="/blog" className="text-zk-ink no-underline hover:text-zk-accent">
        Blog
      </Link>
      <Link href="/guides/introduction" className="text-zk-ink no-underline hover:text-zk-accent">
        Docs
      </Link>
      <a
        href="https://github.com/zerkerlabs/treeship"
        className="rounded-full border border-zk-hairline px-3 py-1.5 text-zk-ink no-underline hover:border-zk-hairline-strong"
      >
        GitHub
      </a>
    </div>
  );
}
