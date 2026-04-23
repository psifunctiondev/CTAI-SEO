# Yoast SEO & On-Page Findings
## Catherine Truman Architects — catherinetrumanarchitects.com
**Prepared by:** Psi Function | **Date:** April 23, 2026

---

## Executive Summary

The Yoast SEO plugin (free version) is installed and doing solid work on the **project pages** — all 42 projects have custom titles, meta descriptions, and OG images. That's the good news. The issues are concentrated on the **core pages** (Homepage, Contact, Awards) and **site-wide settings** where some important pieces are missing or misconfigured.

We've organized everything into three tiers: things that need fixing, things that need adding, and optimizations for later.

---

## 🔴 Needs Fixing (Immediate)

### 1. Contact Page Is a Ghost Copy of the Homepage

| | Homepage | Contact |
|---|---|---|
| Title | Woman-Owned Architecture Studio, Modern Home Design \| Boston | Woman-Owned Architecture Studio, Modern Home Design \| Boston |
| Meta Description | Women-owned Boston architecture studio… | Women-owned Boston architecture studio… |
| Canonical URL | `https://catherinetrumanarchitects.com/` | `https://catherinetrumanarchitects.com/` ← **wrong** |

The Contact page has a contact form and a map, but Google sees it as a duplicate of the Homepage because it shares the same title, description, and canonical URL. This means:
- Google may ignore the Contact page entirely
- People searching "Catherine Truman Architects contact" or "Boston architect phone number" won't find a properly optimized result

**Fix:** In WordPress, edit the Contact page → Yoast SEO panel → set:
- **Title:** `Contact Catherine Truman Architects | Boston Architecture Studio`
- **Meta description:** `Reach Catherine Truman Architects at our Boston studio. Contact us to discuss your residential renovation, new construction, or interior design project.`
- **Canonical:** Make sure it points to `/contact/` (not `/`)

**Effort:** 2 minutes in WordPress

---

### 2. Homepage Has No H1 Heading

The Homepage has **zero heading tags** — no H1, no H2, nothing. Google uses the H1 as a primary signal for what the page is about. Without one, the page is relying entirely on the `<title>` tag.

This is a known Divi builder issue — the slider module and section headers don't always generate proper HTML heading tags.

**Fix:** In Divi, add an H1 to the homepage. It can be visually styled however you want — Google only cares about the HTML. Something like:
> `<h1>Boston Architecture Studio — Modern Homes & Thoughtful Renovations</h1>`

**Effort:** 5 minutes in Divi builder

---

### 3. Mobile Zoom Is Disabled

The site's viewport meta tag includes `user-scalable=0, maximum-scale=1.0`, which **prevents users from pinching to zoom** on mobile devices. This is:
- **An accessibility violation** (WCAG 2.1 Level AA, Success Criterion 1.4.4)
- **A negative SEO signal** — Google's mobile-friendly test flags this
- **Frustrating for users** trying to zoom into project photos (which is exactly what architecture clients want to do)

**Fix:** In the Divi theme settings or the child theme's `header.php`, change:
```
maximum-scale=1.0, user-scalable=0
```
to:
```
maximum-scale=5.0, user-scalable=1
```

**Effort:** 2 minutes in theme settings or header file

---

## 🟡 Needs Adding (Important)

### 4. No LocalBusiness / Organization Schema

The site has **zero structured data** beyond Yoast's default WebPage and BreadcrumbList schemas. For a physical architecture firm in Boston, this is a significant missed opportunity.

**What's missing:**
- `LocalBusiness` or `ProfessionalService` schema — tells Google this is a real business with an address, phone number, hours
- `Organization` schema — connects the business name, logo, and social profiles

**Why it matters:**
- Enables the **Google Business Knowledge Panel** (the info box that appears on the right side of search results)
- Helps with **local pack rankings** ("architects near me")
- Powers **rich results** with star ratings, hours, and contact info

**Fix:** Add JSON-LD structured data to the Homepage. This can be done via:
- Yoast SEO's Local SEO add-on ($$$) — probably not worth it
- A simple code snippet in the child theme's `header.php` or via the "Code Snippets" plugin (already installed — we saw `wp_snippets` table in the database)
- We can provide the exact JSON-LD code ready to paste

**Effort:** 10 minutes (paste code snippet)

---

### 5. OG Images Missing on Key Pages

When someone shares a link on LinkedIn, Facebook, or iMessage, the platform pulls the OG (Open Graph) image to show a preview. Three important pages have no OG image:

| Page | OG Image |
|---|---|
| Homepage | ❌ Missing |
| Projects (portfolio listing) | ❌ Missing |
| Press & Awards | ❌ Missing |
| About | ✅ Has one |
| All 42 project pages | ✅ All have one |

**Why it matters:** The Homepage is the most-shared page. Without an OG image, LinkedIn and Facebook show either nothing or pull a random image from the page. For an architecture firm where visual impression is everything, this matters.

**Fix:** In WordPress, edit each page → Yoast SEO → Social tab → upload a Featured Image or specific OG image. The homepage should use a strong hero shot or the firm's logo/brand image.

**Effort:** 5 minutes per page

---

### 6. Awards Page Is a Shadow of Press

The `/awards/` URL exists and has content, but it uses the **same title, description, and canonical as the `/press/` page**. Similar to the Contact page issue — Google sees this as a duplicate.

| | Press | Awards |
|---|---|---|
| Title | Press & Recognition \| Catherine Truman Architects | Press & Recognition \| Catherine Truman Architects |
| Canonical | `/press/` | `/press/` |

**Options:**
- **If they're meant to be the same page:** Remove one and redirect to the other (301 redirect)
- **If they're separate:** Give Awards its own title, description, and canonical

**Effort:** 5 minutes either way

---

## ✅ What's Working Well

These are worth knowing — and worth protecting during any site changes:

### Project Pages (All 42) — Excellent
- ✅ Every project has a custom, descriptive title with location keywords
- ✅ Every project has a unique meta description
- ✅ Every project has an OG image for social sharing
- ✅ Proper canonical URLs
- ✅ BreadcrumbList schema for navigation context
- ✅ `max-image-preview:large` robots directive (tells Google it can show large image previews)

### About Page — Solid
- ✅ Custom title and description
- ✅ OG image set
- ✅ Has an H1 heading
- ✅ Proper canonical

### Site-Wide
- ✅ Yoast is generating XML sitemaps (6 sitemaps: posts, pages, projects, press, team, categories)
- ✅ `robots.txt` is accessible (was returning 404 earlier — now fixed)
- ✅ All external links open in new tabs with `target="_blank"`

---

## 📊 Quick Reference: Page-by-Page Status

| Page | Title | Description | H1 | OG Image | Canonical | Schema |
|---|---|---|---|---|---|---|
| Homepage | ✅ | ✅ | ❌ | ❌ | ✅ | Basic only |
| About | ✅ | ✅ | ✅ | ✅ | ✅ | Basic only |
| Contact | ❌ Duplicate | ❌ Duplicate | ❌ | ❌ | ❌ Wrong | Basic only |
| Projects | ✅ | ✅ | ❌ | ❌ | ✅ | Basic only |
| Press | ✅ | ✅ | ❌ | ❌ | ✅ | Basic only |
| Awards | ❌ Duplicate | ❌ Duplicate | ❌ | ❌ | ❌ Wrong | Basic only |
| 42 Projects | ✅ All | ✅ All | ❌ None | ✅ All | ✅ All | Basic only |

---

## 🔗 Minor: External Link Security

Five press/awards links to external publications are missing `rel="noopener noreferrer"`:
- realestate.boston.com (Deerfield article)
- bostonmagazine.com (Cambridge kitchen)
- metrocorpmedia.com (Boston Home flipbook)
- modernluxury.com (Back Bay home)
- nehomemag.com (pool house article)

Not an SEO factor, but a minor security best practice. The linked pages can technically access `window.opener` to manipulate the referring tab. Easy fix when editing those pages.

---

## Recommended Priority Order

| # | Item | Impact | Effort | Who |
|---|---|---|---|---|
| 1 | Fix Contact page (title, desc, canonical) | High | 2 min | Macy or web designer |
| 2 | Add H1 to Homepage | High | 5 min | Web designer (Divi) |
| 3 | Enable mobile zoom | Medium | 2 min | Web designer |
| 4 | Add OG images to Homepage, Projects, Press | Medium | 15 min | Macy |
| 5 | Fix Awards page (deduplicate from Press) | Medium | 5 min | Macy or web designer |
| 6 | Add LocalBusiness schema | High | 10 min | Psi Function (we provide the code) |
| 7 | Fix noopener on 5 press links | Low | 2 min | Anyone |

Items 1-5 can all be done in a single WordPress session — about 30 minutes total.

---

*Report generated from live site analysis on April 23, 2026.*
*Data sources: WordPress REST API, Yoast SEO metadata, page source analysis.*

**Psi Function** | doxa@psifunction.com
