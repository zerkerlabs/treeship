import { source } from '@/lib/source';
import { getLLMText } from '@/lib/llms';

// The entire docs corpus as one clean-markdown document, generated from the
// source at build. One fetch and an agent has everything.
export const revalidate = false;

export async function GET() {
  const pages = source.getPages();
  const docs = await Promise.all(pages.map(getLLMText));
  return new Response(docs.join('\n\n---\n\n'), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
}
