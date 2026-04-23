#!/usr/bin/env python3
"""
wp_inventory.py — CTAI WordPress Media Inventory Builder

Enumerates all media items via the WordPress REST API, classifies them,
fetches post/page titles in bulk, and outputs JSON + text reports.
"""

import json
import re
import time
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any
import urllib.request
import urllib.error
import urllib.parse

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SITE_URL = "https://catherinetrumanarchitects.com"
API_BASE = f"{SITE_URL}/wp-json/wp/v2"
SECRETS_FILE = Path("/Users/doxa/.openclaw/workspace/.secrets/ctai-wp-api.txt")
OUTPUT_DIR = Path("/Users/doxa/.openclaw/workspace/CTAI-SEO/analysis")

PAGE_SIZE = 100
REQUEST_DELAY = 0.5  # seconds between paginated media requests

# Keywords for "safe" pilot candidate identification
SAFE_KEYWORDS = [
    "kitchen", "bathroom", "bath", "exterior", "living", "bedroom",
    "dining", "entry", "foyer", "stair", "library", "office",
    "pool", "garden", "patio", "deck", "barn", "fireplace",
    "master", "mudroom", "laundry", "pantry", "terrace", "facade",
    "courtyard", "studio", "hallway", "loft", "renovation", "addition",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_credentials() -> tuple:
    """Parse username and application password from secrets file."""
    text = SECRETS_FILE.read_text()
    username = "psifunction"
    password = None
    for line in text.splitlines():
        if line.startswith("Application Password:"):
            password = line.split(":", 1)[1].strip()
            break
        if line.startswith("Username:"):
            username = line.split(":", 1)[1].strip()
    if not password:
        raise ValueError("Could not find Application Password in secrets file")
    return username, password


def make_auth_header(username: str, password: str) -> Dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "User-Agent": "CTAI-SEO-Inventory/1.0",
    }


def api_get(url: str, headers: Dict[str, str]) -> tuple:
    """Fetch URL, return (data, response_headers). Raises on HTTP error."""
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
        resp_headers = dict(resp.headers)
    return data, resp_headers


def classify_image_type(filename: str) -> str:
    """Classify a filename as full_res, thumbnail, or original."""
    name = Path(filename).name
    if "-scaled" in name:
        return "full_res"
    # thumbnail pattern: ends with -NNNxNNN before extension
    if re.search(r"-\d{2,4}x\d{2,4}\.", name):
        return "thumbnail"
    return "original"


def extract_year(file_path: str) -> Optional[str]:
    """Extract year from path like '2023/03/image.jpg'."""
    m = re.match(r"(\d{4})/", file_path or "")
    return m.group(1) if m else None


def get_thumbnail_url(item: Dict[str, Any]) -> Optional[str]:
    """Get a small thumbnail URL for the image."""
    sizes = (item.get("media_details") or {}).get("sizes") or {}
    for size in ("thumbnail", "medium", "medium_large"):
        if size in sizes:
            return sizes[size].get("source_url")
    return item.get("source_url")  # fall back to source


def is_safe_candidate(title: str, file_path: str, post_title: Optional[str]) -> bool:
    """Check if an image is a 'safe' pilot candidate based on keywords."""
    combined = " ".join(filter(None, [title, file_path, post_title or ""])).lower()
    return any(kw in combined for kw in SAFE_KEYWORDS)


# ---------------------------------------------------------------------------
# Main inventory logic
# ---------------------------------------------------------------------------

def fetch_all_media(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Paginate through all media items and return raw API records."""
    all_items = []
    page = 1
    total_pages = None

    while True:
        url = f"{API_BASE}/media?per_page={PAGE_SIZE}&page={page}&_fields=id,title,alt_text,source_url,media_type,mime_type,media_details,post,date"
        print(f"  Fetching media page {page}{f'/{total_pages}' if total_pages else ''}…")
        try:
            data, resp_headers = api_get(url, headers)
        except urllib.error.HTTPError as e:
            if e.code == 400 and page > 1:
                print(f"  Page {page} returned 400 — assuming end of results.")
                break
            raise

        if not data:
            break

        all_items.extend(data)

        if total_pages is None:
            # Header keys may be lowercase
            tp = resp_headers.get("X-WP-TotalPages") or resp_headers.get("x-wp-totalpages")
            if tp:
                total_pages = int(tp)
                print(f"  Total pages: {total_pages}")

        if total_pages and page >= total_pages:
            break
        if len(data) < PAGE_SIZE:
            break

        page += 1
        time.sleep(REQUEST_DELAY)

    print(f"  Fetched {len(all_items)} total media items.")
    return all_items


def batch_fetch_post_titles(post_ids: List[int], headers: Dict[str, str]) -> Dict[int, str]:
    """Fetch post/page titles for a list of post IDs, batching by 100."""
    if not post_ids:
        return {}

    titles: Dict[int, str] = {}
    unique_ids = list(set(post_ids))
    batch_size = 100

    for i in range(0, len(unique_ids), batch_size):
        batch = unique_ids[i:i + batch_size]
        include_param = ",".join(str(pid) for pid in batch)

        # Try posts, pages, and custom post type 'project'
        for endpoint in ("posts", "pages", "project"):
            url = f"{API_BASE}/{endpoint}?include={include_param}&per_page={batch_size}&_fields=id,title"
            try:
                data, _ = api_get(url, headers)
                for item in data:
                    pid = item.get("id")
                    title = (item.get("title") or {}).get("rendered", "")
                    if pid and title:
                        titles[pid] = title
            except urllib.error.HTTPError:
                pass
            time.sleep(0.2)

    return titles


def build_inventory(raw_items: List[Dict[str, Any]], post_titles: Dict[int, str]) -> List[Dict[str, Any]]:
    """Transform raw API items into structured inventory records."""
    inventory = []

    for item in raw_items:
        media_type = item.get("media_type", "")
        mime_type = item.get("mime_type", "")

        # Skip non-images
        if media_type != "image":
            continue

        media_details = item.get("media_details") or {}
        file_path = media_details.get("file", "")
        filename = Path(file_path).name if file_path else ""

        alt_text = (item.get("alt_text") or "").strip()
        needs_alt = not bool(alt_text)

        post_id = item.get("post") or None
        post_title = post_titles.get(post_id) if post_id else None

        upload_date = (item.get("date") or "")[:10]  # YYYY-MM-DD
        year = extract_year(file_path)

        image_type = classify_image_type(filename or file_path)

        title = (item.get("title") or {}).get("rendered", "")

        record = {
            "id": item.get("id"),
            "title": title,
            "alt_text": alt_text,
            "url": item.get("source_url", ""),
            "thumbnail_url": get_thumbnail_url(item),
            "width": media_details.get("width"),
            "height": media_details.get("height"),
            "filesize": media_details.get("filesize"),
            "file_path": file_path,
            "mime_type": mime_type,
            "image_type": image_type,
            "post_id": post_id,
            "post_title": post_title,
            "upload_date": upload_date,
            "year": year,
            "needs_alt": needs_alt,
            "is_safe_candidate": is_safe_candidate(title, file_path, post_title),
        }
        inventory.append(record)

    return inventory


def build_summary(inventory: List[Dict[str, Any]], total_media: int) -> Dict[str, Any]:
    by_type: Dict[str, int] = {}
    by_mime: Dict[str, int] = {}
    by_year: Dict[str, int] = {}
    by_project: Dict[str, int] = {}

    needs_alt_count = 0
    has_alt_count = 0

    for img in inventory:
        itype = img["image_type"]
        by_type[itype] = by_type.get(itype, 0) + 1

        mime = img["mime_type"]
        by_mime[mime] = by_mime.get(mime, 0) + 1

        yr = img.get("year") or "unknown"
        by_year[yr] = by_year.get(yr, 0) + 1

        pt = img.get("post_title") or "Unattached"
        by_project[pt] = by_project.get(pt, 0) + 1

        if img["needs_alt"]:
            needs_alt_count += 1
        else:
            has_alt_count += 1

    return {
        "by_type": by_type,
        "by_mime": by_mime,
        "by_year": by_year,
        "by_project": by_project,
        "needs_alt": needs_alt_count,
        "has_alt": has_alt_count,
    }


def select_pilot_candidates(inventory: List[Dict[str, Any]], max_count: int = 15) -> List[Dict[str, Any]]:
    """Select best pilot candidates for alt text testing."""
    # Priority: needs_alt + full_res/original + attached to post + safe keyword
    def score(img: Dict[str, Any]) -> int:
        s = 0
        if img["needs_alt"]:
            s += 10
        if img["image_type"] in ("full_res", "original"):
            s += 5
        if img["post_id"]:
            s += 3
        if img["is_safe_candidate"]:
            s += 4
        if img.get("width") and img.get("width", 0) > 800:
            s += 2
        return s

    # Deduplicate by post_title to spread across projects
    candidates = sorted(
        [img for img in inventory if img["needs_alt"] and img["image_type"] in ("full_res", "original")],
        key=score,
        reverse=True,
    )

    # Spread across projects
    seen_projects = set()
    pilot: List[Dict[str, Any]] = []
    # First pass: one per project
    for img in candidates:
        pt = img.get("post_title") or "Unattached"
        if pt not in seen_projects:
            seen_projects.add(pt)
            pilot.append(img)
            if len(pilot) >= max_count:
                break

    # Second pass: fill remaining slots
    if len(pilot) < max_count:
        for img in candidates:
            if img not in pilot:
                pilot.append(img)
                if len(pilot) >= max_count:
                    break

    return pilot[:max_count]


def write_text_report(
    output_path: Path,
    inventory: List[Dict[str, Any]],
    summary: Dict[str, Any],
    total_media: int,
    pilot_candidates: List[Dict[str, Any]],
) -> None:
    lines = []
    lines.append("=" * 72)
    lines.append("CTAI WORDPRESS MEDIA INVENTORY REPORT")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("=" * 72)
    lines.append("")

    lines.append("## OVERVIEW")
    lines.append(f"  Total media items (all types): {total_media}")
    lines.append(f"  Total images:                  {len(inventory)}")
    lines.append(f"  Images needing alt text:       {summary['needs_alt']}")
    lines.append(f"  Images with alt text:          {summary['has_alt']}")
    pct = round(summary['needs_alt'] / len(inventory) * 100, 1) if inventory else 0
    lines.append(f"  Coverage gap:                  {pct}% missing alt text")
    lines.append("")

    lines.append("## BY IMAGE TYPE")
    for k, v in sorted(summary["by_type"].items()):
        lines.append(f"  {k:<15} {v:>5}")
    lines.append("")

    lines.append("## BY MIME TYPE")
    for k, v in sorted(summary["by_mime"].items()):
        lines.append(f"  {k:<25} {v:>5}")
    lines.append("")

    lines.append("## BY UPLOAD YEAR")
    for k, v in sorted(summary["by_year"].items()):
        lines.append(f"  {k:<10} {v:>5}")
    lines.append("")

    lines.append("## BY PROJECT / POST (top 30)")
    sorted_projects = sorted(summary["by_project"].items(), key=lambda x: x[1], reverse=True)
    for k, v in sorted_projects[:30]:
        lines.append(f"  {k:<45} {v:>5}")
    lines.append("")

    lines.append("## IMAGES WITH EXISTING ALT TEXT (style reference)")
    lines.append("  These show the existing alt text style on the site:")
    has_alt = [img for img in inventory if not img["needs_alt"]][:20]
    for img in has_alt:
        lines.append(f"  [{img['id']}] {img['title']}")
        lines.append(f"    Alt: \"{img['alt_text']}\"")
        lines.append(f"    File: {img['file_path']}")
        lines.append("")

    lines.append("## PILOT CANDIDATES (safe, identifiable images)")
    for i, img in enumerate(pilot_candidates, 1):
        lines.append(f"  {i:>2}. [{img['id']}] {img['title']}")
        lines.append(f"      File:    {img['file_path']}")
        lines.append(f"      Type:    {img['image_type']}")
        if img.get("post_title"):
            lines.append(f"      Project: {img['post_title']}")
        if img.get("width") and img.get("height"):
            lines.append(f"      Size:    {img['width']}x{img['height']}")
        lines.append(f"      URL:     {img['url']}")
        lines.append("")

    output_path.write_text("\n".join(lines))
    print(f"  Report written: {output_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print("Loading credentials…")
    username, password = load_credentials()
    headers = make_auth_header(username, password)

    print("\nFetching all media items from WordPress REST API…")
    raw_items = fetch_all_media(headers)
    total_media = len(raw_items)

    # Collect unique post IDs
    post_ids = list(set(
        item.get("post")
        for item in raw_items
        if item.get("post") and item.get("media_type") == "image"
    ))
    print(f"\nFetching titles for {len(post_ids)} unique post/page IDs…")
    post_titles = batch_fetch_post_titles(post_ids, headers)
    print(f"  Resolved {len(post_titles)} post/page titles.")

    print("\nBuilding inventory…")
    inventory = build_inventory(raw_items, post_titles)
    print(f"  {len(inventory)} images catalogued.")

    summary = build_summary(inventory, total_media)
    pilot_candidates = select_pilot_candidates(inventory)

    # --- Output 1: Full JSON inventory ---
    json_path = OUTPUT_DIR / "wp_media_inventory.json"
    output = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_media": total_media,
        "total_images": len(inventory),
        "images_needing_alt": summary["needs_alt"],
        "images_with_alt": summary["has_alt"],
        "summary": {
            "by_type": summary["by_type"],
            "by_mime": summary["by_mime"],
            "by_year": summary["by_year"],
            "by_project": summary["by_project"],
        },
        "images": inventory,
    }
    json_path.write_text(json.dumps(output, indent=2))
    print(f"  Inventory JSON written: {json_path}")

    # --- Output 2: Text summary ---
    txt_path = OUTPUT_DIR / "wp_media_inventory.txt"
    write_text_report(txt_path, inventory, summary, total_media, pilot_candidates)

    # --- Output 3: Pilot candidates JSON ---
    pilot_path = OUTPUT_DIR / "wp_pilot_candidates.json"
    pilot_output = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(pilot_candidates),
        "candidates": pilot_candidates,
    }
    pilot_path.write_text(json.dumps(pilot_output, indent=2))
    print(f"  Pilot candidates written: {pilot_path}")

    print("\nDone!")
    print(f"  Total media:        {total_media}")
    print(f"  Total images:       {len(inventory)}")
    print(f"  Needing alt text:   {summary['needs_alt']}")
    print(f"  Already have alt:   {summary['has_alt']}")
    print(f"  Pilot candidates:   {len(pilot_candidates)}")


if __name__ == "__main__":
    main()
