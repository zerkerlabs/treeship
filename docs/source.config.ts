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
      // One category per post; the blog index sorts on it. Vocabulary in
      // lib/taxonomy.ts. Older posts were assigned one on 2026-09-11.
      category: z
        .enum(['release', 'integration', 'guide', 'engineering', 'security', 'perspective', 'announcement'])
        .default('perspective'),
      // The external systems the post is about (harness, protocol, product,
      // standard). Ids from lib/taxonomy.ts SYSTEMS; unknown ids fail the build.
      systems: z.array(z.string()).default([]),
      // The Treeship release the post documents, when it documents one.
      release: z.string().optional(),
      // For a retrospective entry: the date the words were written, when it
      // is not the date the post is filed under.
      written: z.date().transform((d) => d.toISOString().split('T')[0]).optional(),
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
