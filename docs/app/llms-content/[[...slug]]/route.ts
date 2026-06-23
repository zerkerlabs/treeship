import { source } from '@/lib/source';
import { getLLMText } from '@/lib/llms';
import { notFound } from 'next/navigation';

// Per-page clean markdown. The next.config rewrite maps `/<path>.md` here, so
// appending `.md` to any docs URL returns that page as markdown.
export const revalidate = false;

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ slug?: string[] }> },
) {
  const { slug } = await params;
  const page = source.getPage(slug);
  if (!page) notFound();
  const text = await getLLMText(page);
  return new Response(text, {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  });
}

export function generateStaticParams() {
  return source.generateParams();
}
