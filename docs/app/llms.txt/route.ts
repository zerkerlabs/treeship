import { source } from '@/lib/source';
import { SITE } from '@/lib/llms';

// Generated at build from the docs source, so it never drifts. Replaces the
// old hand-maintained public/llms.txt. Follows the llmstxt.org shape: an H1,
// a summary blockquote, then sections of links. Each link points at the
// page's `.md` form so an agent can fetch clean markdown directly.
export const revalidate = false;

const SECTION_TITLES: Record<string, string> = {
  guides: 'Guides',
  concepts: 'Concepts',
  cli: 'CLI',
  reference: 'Reference',
  sdk: 'SDK',
  integrations: 'Integrations',
  api: 'API',
  commerce: 'Commerce',
  about: 'About',
};
const ORDER = Object.keys(SECTION_TITLES);

export function GET() {
  const pages = source.getPages();

  const bySection = new Map<string, typeof pages>();
  for (const page of pages) {
    const section = page.url.split('/').filter(Boolean)[0] ?? 'docs';
    const bucket = bySection.get(section) ?? [];
    bucket.push(page);
    bySection.set(section, bucket);
  }

  const out: string[] = [
    '# Treeship',
    '',
    '> Treeship is a portable trust layer for AI agent workflows. Every action, approval, and handoff becomes a cryptographically signed artifact that verifies offline, without trusting any infrastructure. This is the documentation index for AI agents: append `.md` to any page URL for its clean markdown, or fetch `/llms-full.txt` for the entire corpus in one request.',
    '',
  ];

  const sections = [...bySection.keys()].sort(
    (a, b) => (ORDER.indexOf(a) + 1 || 99) - (ORDER.indexOf(b) + 1 || 99),
  );

  for (const section of sections) {
    out.push(`## ${SECTION_TITLES[section] ?? section}`, '');
    for (const page of bySection.get(section) ?? []) {
      const data = page.data as unknown as { title?: string; description?: string };
      const title = data.title ?? page.url;
      const desc = data.description ? `: ${data.description}` : '';
      out.push(`- [${title}](${SITE}${page.url}.md)${desc}`);
    }
    out.push('');
  }

  return new Response(out.join('\n'), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
}
