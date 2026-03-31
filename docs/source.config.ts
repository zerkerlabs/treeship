import { defineConfig, defineDocs, frontmatterSchema } from 'fumadocs-mdx/config';
import { z } from 'zod';

export const docs = defineDocs({ dir: 'content/docs' });

export const blog = defineDocs({
  dir: 'content/blog',
  docs: {
    schema: frontmatterSchema.extend({
      date: z.date().transform((d) => d.toISOString().split('T')[0]).optional(),
      tags: z.array(z.string()).default([]),
      readTime: z.string().optional(),
    }),
  },
});

export default defineConfig({
  mdxOptions: {
    rehypeCodeOptions: {
      themes: {
        light: 'dark-plus',
        dark: 'dark-plus',
      },
    },
  },
});
