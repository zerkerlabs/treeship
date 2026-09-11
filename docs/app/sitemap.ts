import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';
import { blogSource } from '@/lib/blog';
import { presentValues } from '@/components/blog-list';

const baseUrl = 'https://docs.treeship.dev';

export default function sitemap(): MetadataRoute.Sitemap {
  const docs = source.getPages().map((page) => ({
    url: `${baseUrl}${page.url}`,
    changeFrequency: 'weekly' as const,
    priority: 0.7,
  }));

  const posts = blogSource.getPages().map((page) => ({
    url: `${baseUrl}${page.url}`,
    changeFrequency: 'monthly' as const,
    priority: 0.5,
  }));

  const present = presentValues();
  const listings = [
    ...present.categories.map((c) => ({ url: `${baseUrl}/blog/category/${c}`, changeFrequency: 'weekly' as const, priority: 0.6 })),
    ...present.systems.map((s) => ({ url: `${baseUrl}/blog/system/${s}`, changeFrequency: 'weekly' as const, priority: 0.6 })),
  ];

  return [
    { url: baseUrl, changeFrequency: 'weekly', priority: 1 },
    { url: `${baseUrl}/blog`, changeFrequency: 'weekly', priority: 0.8 },
    ...listings,
    ...docs,
    ...posts,
  ];
}
