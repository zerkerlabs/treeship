import { defineConfig, defineDocs, defineCollections, frontmatterSchema } from 'fumadocs-mdx/config';
import { z } from 'zod';

export const docs = defineDocs({ dir: 'content/docs' });

export const blog = defineCollections({
  type: 'doc',
  dir: 'content/blog',
  schema: frontmatterSchema.extend({
    date: z.string(),
    tags: z.array(z.string()).default([]),
    readTime: z.string().optional(),
  }),
});

export default defineConfig({
  mdxOptions: {
    // rehype and remark plugins if needed
  },
});
