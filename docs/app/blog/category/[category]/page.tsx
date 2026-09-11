import { notFound } from 'next/navigation';
import { BlogChrome } from '../../chrome';
import { BlogList, presentValues } from '@/components/blog-list';
import { CATEGORIES, isCategory } from '@/lib/taxonomy';

export default async function CategoryPage(props: { params: Promise<{ category: string }> }) {
  const { category } = await props.params;
  if (!isCategory(category)) notFound();
  const info = CATEGORIES[category];
  return (
    <>
      <BlogChrome crumb={info.label} />
      <BlogList filter={{ category }} heading={info.label} lede={info.blurb} />
    </>
  );
}

export function generateStaticParams() {
  return presentValues().categories.map((category) => ({ category }));
}

export async function generateMetadata(props: { params: Promise<{ category: string }> }) {
  const { category } = await props.params;
  if (!isCategory(category)) return {};
  const info = CATEGORIES[category];
  const image = `/og?${new URLSearchParams({ title: `${info.label} · Treeship blog`, description: info.blurb, section: 'blog' }).toString()}`;
  return {
    title: `${info.label} · Blog`,
    description: info.blurb,
    alternates: { canonical: `/blog/category/${category}` },
    openGraph: { title: `${info.label} · Treeship blog`, description: info.blurb, url: `/blog/category/${category}`, images: [{ url: image, width: 1200, height: 630 }] },
    twitter: { card: 'summary_large_image', title: `${info.label} · Treeship blog`, images: [image] },
  };
}
