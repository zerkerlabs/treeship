import Link from 'next/link';
import { notFound } from 'next/navigation';
import { BlogChrome } from '../../chrome';
import { BlogList, presentValues } from '@/components/blog-list';
import { SYSTEMS } from '@/lib/taxonomy';

export default async function SystemPage(props: { params: Promise<{ system: string }> }) {
  const { system } = await props.params;
  const info = SYSTEMS[system];
  if (!info) notFound();
  const lede = info.vendor ? `Treeship and ${info.label}, by ${info.vendor}.` : `Treeship and ${info.label}.`;
  return (
    <>
      <BlogChrome crumb={info.label} />
      <BlogList filter={{ system }} heading={info.label} lede={lede} />
      {info.docs && (
        <p className="mx-auto -mt-12 mb-20 w-full max-w-[860px] px-7">
          <Link href={info.docs} className="doc-meta text-zk-ink no-underline hover:text-zk-accent">
            Integration guide →
          </Link>
        </p>
      )}
    </>
  );
}

export function generateStaticParams() {
  return presentValues().systems.map((system) => ({ system }));
}

export async function generateMetadata(props: { params: Promise<{ system: string }> }) {
  const { system } = await props.params;
  const info = SYSTEMS[system];
  if (!info) return {};
  const description = `Posts about Treeship and ${info.label}.`;
  const image = `/og?${new URLSearchParams({ title: `${info.label} · Treeship blog`, description, section: 'blog' }).toString()}`;
  return {
    title: `${info.label} · Blog`,
    description,
    alternates: { canonical: `/blog/system/${system}` },
    openGraph: { title: `${info.label} · Treeship blog`, description, url: `/blog/system/${system}`, images: [{ url: image, width: 1200, height: 630 }] },
    twitter: { card: 'summary_large_image', title: `${info.label} · Treeship blog`, images: [image] },
  };
}
