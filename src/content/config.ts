import { defineCollection, z } from 'astro:content';

const blog = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
    pubDate: z.coerce.date(),
    updatedDate: z.coerce.date().optional(),
    tags: z.array(z.string()),
    draft: z.boolean().default(false),
    difficulty: z.enum(['beginner', 'intermediate', 'advanced']).optional(),
  }),
});

export const collections = { blog };
