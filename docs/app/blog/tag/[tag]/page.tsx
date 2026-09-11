import { notFound } from 'next/navigation';
import { BlogChrome } from '../../chrome';
import { BlogList, presentValues } from '@/components/blog-list';

export default async function TagPage(props: { params: Promise<{ tag: string }> }) {
  const { tag } = await props.params;
  if (!presentValues().tags.includes(tag)) notFound();
  return (
    <>
      <BlogChrome crumb={`#${tag}`} />
      <BlogList filter={{ tag }} heading={`#${tag}`} lede={`Every post tagged ${tag}.`} />
    </>
  );
}

export function generateStaticParams() {
  return presentValues().tags.map((tag) => ({ tag }));
}

export async function generateMetadata(props: { params: Promise<{ tag: string }> }) {
  const { tag } = await props.params;
  return {
    title: `#${tag} · Blog`,
    description: `Every Treeship post tagged ${tag}.`,
    alternates: { canonical: `/blog/tag/${tag}` },
    robots: { index: false, follow: true },
  };
}
