'use client';

import { useState } from 'react';

// Per-page AI actions: copy the page as clean markdown, view the raw `.md`,
// or open it in Claude / ChatGPT. The markdown comes from the same `.md`
// route agents use, so what a human copies is exactly what an agent reads.
export function LLMActions({ url }: { url: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'error'>('idle');
  const mdPath = `${url}.md`;
  const absolute = `https://docs.treeship.dev${mdPath}`;
  const prompt = `Read ${absolute} and help me with it.`;

  async function copy() {
    try {
      const res = await fetch(mdPath);
      await navigator.clipboard.writeText(await res.text());
      setState('copied');
      setTimeout(() => setState('idle'), 2000);
    } catch {
      setState('error');
      setTimeout(() => setState('idle'), 2000);
    }
  }

  const cls =
    'inline-flex items-center gap-1 rounded-md border border-fd-border bg-fd-secondary/50 px-2.5 py-1 text-xs font-medium text-fd-muted-foreground transition-colors hover:bg-fd-accent hover:text-fd-accent-foreground no-underline';

  return (
    <div className="not-prose mb-6 flex flex-wrap items-center gap-2">
      <button type="button" onClick={copy} className={cls}>
        {state === 'copied' ? 'Copied' : state === 'error' ? 'Copy failed' : 'Copy as Markdown'}
      </button>
      <a href={mdPath} className={cls}>
        View as Markdown
      </a>
      <a
        href={`https://claude.ai/new?q=${encodeURIComponent(prompt)}`}
        target="_blank"
        rel="noreferrer"
        className={cls}
      >
        Open in Claude
      </a>
      <a
        href={`https://chatgpt.com/?q=${encodeURIComponent(prompt)}`}
        target="_blank"
        rel="noreferrer"
        className={cls}
      >
        Open in ChatGPT
      </a>
    </div>
  );
}
