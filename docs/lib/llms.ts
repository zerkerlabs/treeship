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
  // (e.g. component imports). Strip them so agents get clean prose, then
  // collapse the blank lines they leave behind.
  const body = (await data.getText('processed'))
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
