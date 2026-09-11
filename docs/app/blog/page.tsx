import { BlogChrome } from './chrome';
import { BlogList } from '@/components/blog-list';

const description =
  'Releases, integrations, guides and engineering notes: what Treeship signs, for which systems, and how to check it.';

const indexImage = `/og?${new URLSearchParams({
  title: 'Treeship blog',
  description,
  section: 'blog',
}).toString()}`;

export const metadata = {
  title: 'Blog',
  description,
  alternates: { canonical: '/blog' },
  openGraph: {
    title: 'Treeship blog',
    description,
    url: '/blog',
    images: [{ url: indexImage, width: 1200, height: 630, alt: 'Treeship blog' }],
  },
  twitter: { card: 'summary_large_image', title: 'Treeship blog', images: [indexImage] },
};

export default function BlogIndex() {
  return (
    <>
      <BlogChrome crumb="Writing" />
      <BlogList filter={{}} heading="Blog" lede={description} />
    </>
  );
}
