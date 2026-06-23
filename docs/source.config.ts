import { defineConfig, defineDocs, frontmatterSchema } from 'fumadocs-mdx/config';
import { z } from 'zod';

export const docs = defineDocs({
  dir: 'content/docs',
  // Keep processed markdown so the agent routes (per-page `.md`,
  // `/llms-full.txt`) can emit each page via getText('processed').
  docs: {
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
});

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
