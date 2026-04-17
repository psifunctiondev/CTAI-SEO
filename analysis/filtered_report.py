"""
CTAI Filtered Traffic Report

Produces a report with three views:
1. Full traffic (everything)
2. Known IP breakdown (admin, hosting, scanner activity)
3. Organic-only traffic (everything minus known IPs)

Known IPs are tagged and counted, never removed.
Catherine's team can verify the IP classifications and see clean organic data.

Uses both the known IP registry (hardcoded, verified) and behavioral
classification (pattern-matching, adapts to IP changes).
"""

import json
import os
import sys
from datetime import datetime
from collections import defaultdict, Counter

from log_parser import parse_all_logs, LogEntry
from known_ips import KNOWN_IPS, ROLE_DESCRIPTIONS
from ip_classifier import classify_all, EXTENDED_ROLE_DESCRIPTIONS, IPProfile


def tag_entries(entries):
    """
    Split entries into organic and non-organic using behavioral classifier.
    Returns (organic_entries, known_entries, known_summary, profiles).
    """
    # Classify all IPs
    profiles = classify_all(entries)

    organic = []
    known = []
    known_summary = defaultdict(lambda: {
        "count": 0,
        "ips": set(),
        "page_views": 0,
        "daily": Counter(),
    })

    for e in entries:
        p = profiles.get(e.ip)
        role = p.role if p else "organic"
        if role != "organic":
            known.append(e)
            s = known_summary[role]
            s["count"] += 1
            s["ips"].add(e.ip)
            if e.is_page and e.status == 200:
                s["page_views"] += 1
            s["daily"][e.timestamp.strftime("%Y-%m-%d")] += 1
        else:
            organic.append(e)

    return organic, known, known_summary, profiles


def weekly_comparison(entries: list[LogEntry], organic: list[LogEntry]) -> list[dict]:
    """Weekly summary comparing total vs organic traffic."""
    def weekly_stats(data: list[LogEntry]) -> dict:
        weeks = defaultdict(lambda: {
            "human_page_views": 0,
            "unique_ips": set(),
            "total_requests": 0,
        })
        for e in data:
            iso = e.timestamp.isocalendar()
            week_key = f"{iso[0]}-W{iso[1]:02d}"
            w = weeks[week_key]
            w["total_requests"] += 1
            if e.traffic_class == "human" and e.is_page and e.status == 200:
                w["human_page_views"] += 1
            if e.traffic_class == "human":
                w["unique_ips"].add(e.ip)
        return weeks

    all_weeks = weekly_stats(entries)
    org_weeks = weekly_stats(organic)

    result = []
    for week_key in sorted(set(list(all_weeks.keys()) + list(org_weeks.keys()))):
        aw = all_weeks.get(week_key, {"human_page_views": 0, "unique_ips": set(), "total_requests": 0})
        ow = org_weeks.get(week_key, {"human_page_views": 0, "unique_ips": set(), "total_requests": 0})

        result.append({
            "week": week_key,
            "total_requests": aw["total_requests"],
            "total_human_pv": aw["human_page_views"],
            "total_unique_visitors": len(aw["unique_ips"]),
            "organic_requests": ow["total_requests"],
            "organic_human_pv": ow["human_page_views"],
            "organic_unique_visitors": len(ow["unique_ips"]),
            "filtered_requests": aw["total_requests"] - ow["total_requests"],
            "filtered_pv": aw["human_page_views"] - ow["human_page_views"],
        })
    return result


def daily_comparison(entries: list[LogEntry], organic: list[LogEntry]) -> dict:
    """Daily unique visitor comparison."""
    def daily_uv(data: list[LogEntry]) -> dict:
        daily = defaultdict(set)
        for e in data:
            if e.traffic_class == "human":
                day = e.timestamp.strftime("%Y-%m-%d")
                daily[day].add(e.ip)
        return {d: len(ips) for d, ips in sorted(daily.items())}

    all_daily = daily_uv(entries)
    org_daily = daily_uv(organic)

    return {
        "all_traffic": all_daily,
        "organic_only": org_daily,
    }


def top_pages_comparison(entries: list[LogEntry], organic: list[LogEntry], n: int = 25) -> list[dict]:
    """Top pages with total vs organic counts."""
    def page_counts(data: list[LogEntry]) -> Counter:
        pages = Counter()
        for e in data:
            if e.traffic_class == "human" and e.is_page and e.status == 200:
                path = e.path.rstrip("/") or "/"
                pages[path] += 1
        return pages

    all_pages = page_counts(entries)
    org_pages = page_counts(organic)

    # Merge and sort by organic count
    all_paths = set(list(all_pages.keys()) + list(org_pages.keys()))
    result = []
    for path in all_paths:
        result.append({
            "path": path,
            "total_views": all_pages.get(path, 0),
            "organic_views": org_pages.get(path, 0),
            "known_ip_views": all_pages.get(path, 0) - org_pages.get(path, 0),
        })
    result.sort(key=lambda x: x["organic_views"], reverse=True)
    return result[:n]


def known_ip_detail_table(known_entries, profiles: dict) -> list[dict]:
    """Detailed breakdown of each non-organic IP for verification."""
    by_ip = defaultdict(lambda: {
        "requests": 0,
        "page_views": 0,
        "first_seen": None,
        "last_seen": None,
        "active_days": set(),
        "top_paths": Counter(),
        "status_codes": Counter(),
    })

    for e in known_entries:
        d = by_ip[e.ip]
        d["requests"] += 1
        if e.is_page and e.status == 200:
            d["page_views"] += 1
        ts = e.timestamp
        if d["first_seen"] is None or ts < d["first_seen"]:
            d["first_seen"] = ts
        if d["last_seen"] is None or ts > d["last_seen"]:
            d["last_seen"] = ts
        d["active_days"].add(ts.strftime("%Y-%m-%d"))
        d["top_paths"][e.path.rstrip("/") or "/"] += 1
        d["status_codes"][str(e.status)] += 1

    result = []
    for ip in sorted(by_ip.keys(), key=lambda x: by_ip[x]["requests"], reverse=True):
        d = by_ip[ip]
        p = profiles.get(ip)
        registry_info = KNOWN_IPS.get(ip)
        result.append({
            "ip": ip,
            "role": p.role if p else "unknown",
            "label": (registry_info.label if registry_info
                      else (p.match_reason[:60] if p else "Unknown")),
            "confidence": p.confidence if p else "n/a",
            "match_source": p.match_source if p else "unknown",
            "evidence": (registry_info.evidence if registry_info
                         else (p.match_reason if p else "")),
            "total_requests": d["requests"],
            "page_views": d["page_views"],
            "active_days": len(d["active_days"]),
            "first_seen": d["first_seen"].strftime("%Y-%m-%d") if d["first_seen"] else None,
            "last_seen": d["last_seen"].strftime("%Y-%m-%d") if d["last_seen"] else None,
            "top_paths": d["top_paths"].most_common(5),
            "status_codes": dict(d["status_codes"].most_common()),
        })
    return result


def organic_referrer_analysis(organic: list[LogEntry]) -> dict:
    """Referrer analysis for organic traffic only."""
    search_referrers = Counter()
    social_referrers = Counter()
    other_referrers = Counter()
    direct = 0

    search_domains = {"google.com", "google.co", "bing.com", "yahoo.com",
                      "duckduckgo.com", "yandex.", "baidu.com", "ecosia.org"}
    social_domains = {"facebook.com", "fb.com", "instagram.com", "twitter.com",
                      "x.com", "linkedin.com", "pinterest.com", "reddit.com",
                      "tiktok.com", "youtube.com"}
    internal_domains = {"catherinetrumanarchitects.com", "truman-architects.com",
                        "trumanarchitects.com"}

    for e in organic:
        if e.traffic_class != "human" or not e.is_page or e.status != 200:
            continue

        ref = e.referrer
        if ref == "-" or ref == "":
            direct += 1
            continue

        ref_lower = ref.lower()
        if any(d in ref_lower for d in internal_domains):
            direct += 1
            continue

        if any(d in ref_lower for d in search_domains):
            for d in search_domains:
                if d in ref_lower:
                    search_referrers[d.split(".")[0].capitalize()] += 1
                    break
        elif any(d in ref_lower for d in social_domains):
            for d in social_domains:
                if d in ref_lower:
                    social_referrers[d.split(".")[0].capitalize()] += 1
                    break
        else:
            other_referrers[ref] += 1

    return {
        "direct_or_internal": direct,
        "search_engines": dict(search_referrers.most_common()),
        "social": dict(social_referrers.most_common()),
        "top_other_referrers": [{"url": u, "count": c} for u, c in other_referrers.most_common(15)],
    }


def format_text_report(
    entries, organic, known_entries, known_summary, 
    weekly, pages, ip_details, referrers, daily_uv
) -> str:
    """Format the filtered report as readable text."""
    lines = []
    lines.append("=" * 72)
    lines.append("CTAI TRAFFIC ANALYSIS — FILTERED REPORT")
    lines.append("Catherine Truman Architects & Interiors")
    lines.append(f"Period: {entries[0].timestamp.strftime('%Y-%m-%d')} to "
                 f"{entries[-1].timestamp.strftime('%Y-%m-%d')}")
    lines.append(f"Report generated: {datetime.now().isoformat()}")
    lines.append("=" * 72)

    # --- Section 1: Overview ---
    lines.append(f"\n{'─' * 60}")
    lines.append("SECTION 1: TRAFFIC OVERVIEW")
    lines.append(f"{'─' * 60}")
    lines.append(f"Total log entries:          {len(entries):>10,}")
    lines.append(f"Known IP entries:           {len(known_entries):>10,}")
    lines.append(f"Organic entries:            {len(organic):>10,}")
    lines.append(f"Known IP share:             {len(known_entries)/len(entries)*100:>9.1f}%")
    lines.append(f"\nNon-organic IP breakdown by role:")
    all_roles = {**ROLE_DESCRIPTIONS, **EXTENDED_ROLE_DESCRIPTIONS}
    for role, s in sorted(known_summary.items(), key=lambda x: x[1]['count'], reverse=True):
        desc = all_roles.get(role, role)
        lines.append(f"  {desc:35s}  {s['count']:>8,} requests  "
                     f"({len(s['ips'])} IPs, {s['page_views']:,} page views)")

    # --- Section 2: Known IP Verification Table ---
    lines.append(f"\n{'─' * 60}")
    lines.append("SECTION 2: KNOWN IP VERIFICATION TABLE")
    lines.append("(For Catherine's team to verify IP classifications)")
    lines.append(f"{'─' * 60}")
    for d in ip_details:
        all_roles = {**ROLE_DESCRIPTIONS, **EXTENDED_ROLE_DESCRIPTIONS}
        role_label = all_roles.get(d["role"], d["role"])
        lines.append(f"\n  IP: {d['ip']}")
        lines.append(f"    Role:        {role_label}")
        src_tag = "[registry]" if d.get('match_source') == 'registry' else "[behavioral]"
        lines.append(f"    Label:       {d['label']}")
        lines.append(f"    Matched by:  {src_tag}  Confidence: {d['confidence']}")
        lines.append(f"    Requests:    {d['total_requests']:,}  ({d['page_views']:,} page views)")
        lines.append(f"    Active:      {d['active_days']} days  ({d['first_seen']} → {d['last_seen']})")
        lines.append(f"    Evidence:    {d['evidence'][:120]}")
        if d["top_paths"]:
            lines.append(f"    Top paths:")
            for path, count in d["top_paths"]:
                lines.append(f"      {count:>5,}  {path[:70]}")

    # --- Section 3: Weekly Trends (Total vs Organic) ---
    lines.append(f"\n{'─' * 60}")
    lines.append("SECTION 3: WEEKLY TRENDS — TOTAL vs ORGANIC")
    lines.append(f"{'─' * 60}")
    lines.append(f"{'Week':>10}  {'Total PV':>10} {'Organic PV':>11} {'Filtered':>10}  "
                 f"{'Total UV':>10} {'Organic UV':>11}")
    lines.append(f"{'':>10}  {'':>10} {'':>11} {'':>10}  {'':>10} {'':>11}")
    for w in weekly:
        lines.append(
            f"{w['week']:>10}  {w['total_human_pv']:>10,} {w['organic_human_pv']:>11,} "
            f"{w['filtered_pv']:>10,}  {w['total_unique_visitors']:>10,} "
            f"{w['organic_unique_visitors']:>11,}"
        )
    # Totals
    tot_pv = sum(w["total_human_pv"] for w in weekly)
    org_pv = sum(w["organic_human_pv"] for w in weekly)
    flt_pv = sum(w["filtered_pv"] for w in weekly)
    lines.append(f"{'─'*10}  {'─'*10} {'─'*11} {'─'*10}  {'─'*10} {'─'*11}")
    lines.append(f"{'TOTAL':>10}  {tot_pv:>10,} {org_pv:>11,} {flt_pv:>10,}")
    lines.append(f"\n  PV = Page Views (human, status 200)")
    lines.append(f"  UV = Unique Visitors (unique IPs with human classification)")
    lines.append(f"  Filtered = requests attributed to known admin/hosting/scanner IPs")

    # --- Section 4: Daily Unique Visitors ---
    lines.append(f"\n{'─' * 60}")
    lines.append("SECTION 4: DAILY UNIQUE VISITORS — TOTAL vs ORGANIC")
    lines.append(f"{'─' * 60}")
    all_uv = daily_uv["all_traffic"]
    org_uv = daily_uv["organic_only"]
    max_uv = max(max(all_uv.values(), default=1), max(org_uv.values(), default=1))
    for day in sorted(set(list(all_uv.keys()) + list(org_uv.keys()))):
        a = all_uv.get(day, 0)
        o = org_uv.get(day, 0)
        bar = "█" * int(o / max_uv * 40) if max_uv > 0 else ""
        lines.append(f"  {day}  Total:{a:>4}  Organic:{o:>4}  {bar}")

    # --- Section 5: Top Pages (Organic) ---
    lines.append(f"\n{'─' * 60}")
    lines.append("SECTION 5: TOP PAGES — ORGANIC vs TOTAL")
    lines.append(f"{'─' * 60}")
    lines.append(f"  {'#':>3}  {'Organic':>8} {'Total':>8} {'Known':>8}  Path")
    for i, p in enumerate(pages[:25], 1):
        lines.append(
            f"  {i:>3}. {p['organic_views']:>8,} {p['total_views']:>8,} "
            f"{p['known_ip_views']:>8,}  {p['path'][:55]}"
        )

    # --- Section 6: Organic Referrer Sources ---
    ref = referrers
    lines.append(f"\n{'─' * 60}")
    lines.append("SECTION 6: ORGANIC REFERRER SOURCES")
    lines.append(f"{'─' * 60}")
    lines.append(f"  Direct / internal navigation:  {ref['direct_or_internal']:>6,}")
    if ref["search_engines"]:
        lines.append(f"\n  Organic Search:")
        for engine, count in ref["search_engines"].items():
            lines.append(f"    {engine:20s} {count:>6,}")
    if ref["social"]:
        lines.append(f"\n  Social:")
        for platform, count in ref["social"].items():
            lines.append(f"    {platform:20s} {count:>6,}")
    if ref["top_other_referrers"]:
        lines.append(f"\n  Other External:")
        for r in ref["top_other_referrers"][:10]:
            lines.append(f"    {r['count']:>6,}  {r['url'][:70]}")

    # --- Section 7: Known IP Daily Activity (for spike verification) ---
    lines.append(f"\n{'─' * 60}")
    lines.append("SECTION 7: KNOWN IP DAILY ACTIVITY")
    lines.append("(Verify these spikes match known work periods)")
    lines.append(f"{'─' * 60}")
    all_roles = {**ROLE_DESCRIPTIONS, **EXTENDED_ROLE_DESCRIPTIONS}
    for role in ["admin_designer", "admin_content", "wp_recon"]:
        s = known_summary.get(role)
        if not s:
            continue
        desc = all_roles.get(role, role)
        lines.append(f"\n  {desc}:")
        for day, count in sorted(s["daily"].items()):
            bar = "█" * min(count // 20, 50)
            lines.append(f"    {day}  {count:>6,}  {bar}")

    lines.append(f"\n{'=' * 72}")
    lines.append("END OF FILTERED REPORT")
    lines.append(f"{'=' * 72}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "..", "access_logs"
    )

    print(f"Parsing logs from: {log_dir}")
    entries = parse_all_logs(log_dir)
    print(f"Total entries: {len(entries):,}")

    print("\nClassifying IPs (registry + behavioral)...")
    organic, known_entries, known_summary, profiles = tag_entries(entries)
    print(f"  Non-organic entries: {len(known_entries):,}")
    print(f"  Organic entries:     {len(organic):,}")

    print("\nGenerating comparison data...")
    weekly = weekly_comparison(entries, organic)
    pages = top_pages_comparison(entries, organic)
    ip_details = known_ip_detail_table(known_entries, profiles)
    referrers = organic_referrer_analysis(organic)
    daily_uv = daily_comparison(entries, organic)

    # Save JSON
    output_dir = os.path.dirname(__file__)
    report_data = {
        "report_generated": datetime.now().isoformat(),
        "date_range": {
            "start": entries[0].timestamp.strftime("%Y-%m-%d"),
            "end": entries[-1].timestamp.strftime("%Y-%m-%d"),
        },
        "summary": {
            "total_entries": len(entries),
            "known_ip_entries": len(known_entries),
            "organic_entries": len(organic),
        },
        "known_ip_breakdown": {
            role: {
                "description": EXTENDED_ROLE_DESCRIPTIONS.get(
                    role, ROLE_DESCRIPTIONS.get(role, role)),
                "requests": s["count"],
                "unique_ips": len(s["ips"]),
                "page_views": s["page_views"],
            }
            for role, s in known_summary.items()
        },
        "known_ip_details": ip_details,
        "weekly_comparison": weekly,
        "daily_unique_visitors": daily_uv,
        "top_pages_comparison": pages,
        "organic_referrers": referrers,
    }

    json_path = os.path.join(output_dir, "report_filtered.json")
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2, default=str)
    print(f"\nJSON report: {json_path}")

    # Save text
    text = format_text_report(
        entries, organic, known_entries, known_summary,
        weekly, pages, ip_details, referrers, daily_uv
    )
    text_path = os.path.join(output_dir, "report_filtered.txt")
    with open(text_path, "w") as f:
        f.write(text)
    print(f"Text report: {text_path}")

    print(f"\n{text}")
