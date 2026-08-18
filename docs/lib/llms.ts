import { source } from '@/lib/source';
import type { InferPageType } from 'fumadocs-core/source';

export const SITE = 'https://docs.treeship.dev';

type PageData = {
  title?: string;
  description?: string;
  getText: (type: 'raw' | 'processed') => Promise<string>;
};

/**
 * Render one docs page as clean, self-describing markdown for AI agents:
 * a title, its canonical URL, the description, then the processed body
 * (MDX components flattened to markdown). This is the single source the
 * `.md` per-page route and `/llms-full.txt` both emit, so there is no
 * parallel copy to keep in sync.
 */
export async function getLLMText(
  page: InferPageType<typeof source>,
): Promise<string> {
  const data = page.data as unknown as PageData;
  // Processed markdown still carries MDX `import`/`export` statement lines
  // (e.g. component imports) and the component tags themselves. Strip both so
  // agents get clean prose, then collapse the blank lines they leave behind.
  const body = flattenMdxComponents(await data.getText('processed'))
    .replace(/^(?:import|export)\s.*$/gm, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  const header = [
    `# ${data.title ?? page.url}`,
    `Source: ${SITE}${page.url}`,
    data.description ? `\n> ${data.description}` : '',
  ]
    .filter(Boolean)
    .join('\n');
  return `${header}\n\n${body}`;
}

/** Pull one JSX string attribute out of a tag's attribute blob. */
function attr(tag: string, name: string): string | undefined {
  const m = tag.match(new RegExp(`${name}\\s*=\\s*"([^"]*)"`));
  return m?.[1];
}

/**
 * Flatten the MDX components used across these docs into plain markdown.
 *
 * `getText('processed')` compiles MDX but leaves component tags in the output,
 * so an agent fetching `.md` or `/llms-full.txt` was reading hundreds of
 * `<Callout>` / `<Step>` / `<Tab>` tags as if they were content. Each component
 * becomes the closest markdown equivalent, preserving the information the tag
 * carried (a callout's severity, a tab's label, a card's link) rather than just
 * deleting it.
 */
export function flattenMdxComponents(md: string): string {
  return (
    md
      // <Card title="X" href="/y" description="Z" />  ->  - [X](/y) — Z
      .replace(/<Card\b([^>]*?)\/>/g, (_m, a: string) => {
        const title = attr(a, 'title') ?? '';
        const href = attr(a, 'href');
        const desc = attr(a, 'description');
        const label = href ? `[${title}](${href})` : title;
        return `\n- ${label}${desc ? ` — ${desc}` : ''}`;
      })
      // <Callout type="warn"> ... </Callout>  ->  a labelled blockquote
      .replace(
        /<Callout\b([^>]*)>([\s\S]*?)<\/Callout>/g,
        (_m, a: string, inner: string) => {
          const kind = (attr(a, 'type') ?? 'note').toLowerCase();
          const label =
            kind === 'warn' || kind === 'warning'
              ? 'Warning'
              : kind === 'error' || kind === 'danger'
                ? 'Important'
                : kind === 'tip'
                  ? 'Tip'
                  : 'Note';
          const title = attr(a, 'title');
          // Dedent before quoting. A callout's body is indented in the MDX
          // source; left as-is, four or more leading spaces inside a
          // blockquote render as a code block instead of prose.
          const lines = inner.trim().split('\n');
          const indents = lines
            .filter((l) => l.trim())
            .map((l) => l.match(/^ */)![0].length);
          const strip = indents.length ? Math.min(...indents) : 0;
          const quoted = lines
            .map((l) => {
              const body = l.slice(strip).replace(/^ {4,}/, '  ');
              return body.trim() ? `> ${body}` : '>';
            })
            .join('\n');
          return `\n> **${title ?? label}**\n>\n${quoted}\n`;
        },
      )
      // <Tab value="X"> ... -> a bold label so the grouping survives
      .replace(/<Tab\b([^>]*)>/g, (_m, a: string) => {
        const v = attr(a, 'value') ?? attr(a, 'title');
        return v ? `\n**${v}**\n` : '';
      })
      // Remaining wrappers carry no information a reader needs.
      .replace(/<\/?(?:Tabs|Steps|Step|Cards|Accordions|Accordion|Files|Folder|File)\b[^>]*>/g, '')
      .replace(/<\/Tab>/g, '')
      // The wrappers left their children indented; a flush-left list is what a
      // reader (and a markdown parser) expects.
      .replace(/^[ \t]+(- \[)/gm, '$1')
  );
}
