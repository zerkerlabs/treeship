import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';
import { blogSource } from '@/lib/blog';

const baseUrl = 'https://treeship.dev';

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

  return [
    { url: baseUrl, changeFrequency: 'weekly', priority: 1 },
    { url: `${baseUrl}/blog`, changeFrequency: 'weekly', priority: 0.8 },
    ...docs,
    ...posts,
  ];
}
