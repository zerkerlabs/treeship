import { blog } from '@/.source';
import { loader } from 'fumadocs-core/source';

export const blogSource = loader({
  baseUrl: '/blog',
  source: blog.toFumadocsSource(),
});
