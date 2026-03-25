# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev        # dev server at localhost:4321
npm run build      # production build to ./dist/
npm run preview    # preview the production build
npm run astro      # Astro CLI (e.g. npx astro check for type-checking)
```

Run tests with `npm test` (Playwright). Config at `playwright.config.ts`, tests in `tests/`.

## Architecture

This is **GHOSTWIRE**, an offensive security research blog built with [Astro](https://astro.build) and deployed to GitHub Pages at `https://a5ucanc.github.io`.

### Content

Blog posts live in `src/content/blog/` as Markdown files. The collection schema (defined in `src/content.config.ts`) requires:

```yaml
title: string
description: string
pubDate: date
tags: string[]        # used for tag pages and search
draft: boolean        # draft: true posts are excluded everywhere
updatedDate: date     # optional
```

Draft posts are filtered at build time — they never appear in the blog index, tag pages, or static paths.

### Layout hierarchy

```
BaseLayout.astro          — HTML shell, SEO meta, sticky header, search overlay
  └── PostLayout.astro    — article wrapper with right-side ToC (≥1025px)
```

`BaseLayout` fetches all non-draft posts at SSG time and serialises them into `window.__SEARCH_POSTS__` for the client-side Fuse.js search.

`PostLayout` renders a sticky right-column ToC from `headings` (h2/h3 only) when there are ≥2 qualifying headings. The ToC appears immediately on page load. Client-side JS tracks scroll position to highlight the active section link.

### Styling

All design tokens are CSS custom properties defined in `src/styles/global.css` — the "DEADFALL" palette (phosphor amber `#E8A842`, burnt rust `#D4542A`, institutional olive). Two font variables:

- `--font-mono`: IBM Plex Mono — used for all UI text
- `--font-code`: JetBrains Mono — used inside code blocks

Prose-specific styles (headings, code blocks, tables, blockquotes, copy button) live in `src/styles/prose.css` and are scoped to the `.prose` class. The `PostLayout` imports this file directly.

### Search

Triggered by `/` or `Ctrl/Cmd+K`. `SearchOverlay.astro` receives the serialised posts JSON as a prop from `BaseLayout`, exposes it on `window.__SEARCH_POSTS__`, and runs Fuse.js in a client-side `<script>` block. Results link to `/blog/<slug>` and `/blog/tags/<tag>`.

### Pages and routing

| Route | File |
|---|---|
| `/` | `src/pages/index.astro` — hero + 3 most recent posts |
| `/blog` | `src/pages/blog/index.astro` — full post list |
| `/blog/[slug]` | `src/pages/blog/[...slug].astro` — individual post |
| `/blog/tags/[tag]` | `src/pages/blog/tags/[tag].astro` — posts by tag |
