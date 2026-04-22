# CTAI Website — SEO Image Optimization
### Prepared for Macy Radloff · April 24, 2026

---

## The Opportunity

Catherine's portfolio is stunning — but search engines can't see it. Two quick wins would significantly improve Google visibility:

1. **Alt text is missing from ~90% of portfolio images** — Google Image Search (a major discovery channel for architecture firms) can't index what it can't read.
2. **All images are uncompressed JPEG** — modern browsers support WebP, which is 25-35% smaller at the same quality. Faster pages = better Google ranking.

---

## What We Found (Traffic Audit, Jan–Apr 2026)

| Metric | Value |
|--------|-------|
| Total page views analyzed | 823,949 |
| Unique organic visitors | 19,438 |
| Portfolio images on site | ~625 full-resolution + ~980 thumbnails |
| Images missing alt text | ~90% (estimated 500-1,000+) |
| Average image file size | 632 KB |
| Current image format | 100% JPEG — zero WebP |
| Estimated savings from WebP | ~128 MB total (~210 KB per image) |
| Page load time (TTFB) | 1.1–1.5s (Google target: < 0.8s) |

---

## Proposal: Two-Phase Approach

### Phase 1 — Alt Text (AI-Assisted)

**How it works:**
1. We use AI vision to analyze each portfolio image and draft descriptive alt text (80-125 characters, optimized for search)
2. Your team reviews and edits the drafts in our **Alt Text Review Tool** — a simple web page showing each image alongside its proposed text
3. Once approved, we push the text to WordPress automatically via the REST API

**What we need:**
- A **WordPress Editor account** for Psi Function (can update media metadata but cannot install plugins or change site settings)
- Confirmation that the WordPress REST API is accessible (it is by default)

**Pilot:** We'll start with 5 images to prove the workflow end-to-end before scaling to the full portfolio.

### Phase 2 — WebP Conversion (Plugin)

**Recommended plugin: ShortPixel Image Optimizer**

ShortPixel is the consensus #1 image optimization plugin for WordPress in 2025-2026 across every major review. Here's why:

| Feature | ShortPixel | EWWW (runner-up) |
|---------|-----------|------------------|
| WebP conversion | ✅ Automatic | ✅ Automatic |
| AVIF support | ✅ | ✅ |
| Bulk convert existing images | ✅ One-click | ✅ One-click |
| Browser fallback (JPEG for old browsers) | ✅ Automatic | ✅ Automatic |
| Compression quality | Best-in-class (25-35% savings) | Good (15-25% savings) |
| Free tier | 100 images/month | Unlimited local (lower quality) |
| Pricing for CTAI (~1,600 images) | One-time: **$19.99** (10,000 credits) | $8/month subscription |
| Ease of use | Install → click "Bulk Optimize" → done | More configuration needed |
| Active installs | 400,000+ | 1,000,000+ |
| WordPress.org rating | 4.6/5 | 4.8/5 |

**Our recommendation: ShortPixel** — best compression results, one-time pricing fits this use case perfectly ($19.99 for 10,000 image credits covers the entire CTAI library with room to spare), and the simplest setup. Install, bulk-optimize, forget.

**What ShortPixel does:**
- Converts all existing JPEGs to WebP in one bulk pass
- Automatically converts future uploads
- Serves WebP to modern browsers (99%+) with automatic JPEG fallback for older ones
- No theme or template changes needed — it handles everything
- Keeps original files as backup

**What we need:**
- WordPress Admin access (or Macy/web designer installs the plugin)
- ~10 minutes for initial setup, then bulk conversion runs in the background

---

## What We're Asking For

| Ask | Who | Access Level |
|-----|-----|-------------|
| WordPress Editor account | For Psi Function | Editor role (no plugin/theme access) |
| ShortPixel plugin installed | Macy or web designer | Admin (one-time install) |
| Google Search Console access | Viewer role for Psi Function | Optional but very valuable |

Google Search Console would let us see exactly which search terms drive traffic to the site, which pages rank, and measure improvement over time. It's the single most valuable data source we're currently missing.

---

## Expected Impact

| Change | SEO Impact |
|--------|-----------|
| Alt text on all portfolio images | Opens Google Image Search — major discovery channel for architecture/design firms. Could be the single biggest traffic driver. |
| WebP conversion | 25-35% faster image loading → better Core Web Vitals → Google ranking boost. Estimated ~128 MB bandwidth savings. |
| Both combined | Faster site + searchable images = more organic traffic from people searching for the type of work Catherine does. |

---

## Timeline

| Step | When |
|------|------|
| Pilot: 5 images with alt text | This week (after Thursday meeting) |
| Catherine reviews alt text style | This week |
| ShortPixel install + bulk conversion | Can be done same day as plugin install |
| Full alt text generation + review | 2-3 weeks (batched by project, ~15-25 images per batch) |
| Measure results | 4-6 weeks after changes (SEO takes time to compound) |

---

*Prepared by Psi Function · quinn@psifunction.com*
