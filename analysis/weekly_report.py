#!/usr/bin/env python3
"""
CTAI Weekly SEO Traffic Report

Generates a weekly report for a specific week (default: last complete week)
with full technical detail. Includes week-over-week comparisons.

Can optionally email the report via SMTP.

Usage:
    python weekly_report.py                     # Report for last complete week
    python weekly_report.py --week 2026-W15     # Report for specific week
    python weekly_report.py --email             # Generate and email to Quinn
    python weekly_report.py --email --test      # Dry run (print, don't send)
"""

import json
import os
import sys
import smtplib
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Optional, List, Dict, Tuple

# Add parent dir for imports
sys.path.insert(0, os.path.dirname(__file__))

from log_parser import parse_all_logs, LogEntry
from ip_classifier import classify_all, EXTENDED_ROLE_DESCRIPTIONS, IPProfile
from known_ips import ROLE_DESCRIPTIONS


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SMTP_HOST = "mail.psifunction.com"
SMTP_PORT = 465
SMTP_USER = "doxa@psifunction.com"
REPORT_TO = "quinn@psifunction.com"
REPORT_FROM = "doxa@psifunction.com"

SECRETS_DIR = os.path.expanduser("~/.openclaw/workspace/.secrets")
SMTP_PASS_FILE = os.path.join(SECRETS_DIR, "email-psifunction.txt")

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "access_logs")

INTERNAL_DOMAINS = {
    "catherinetrumanarchitects.com",
    "truman-architects.com",
    "trumanarchitects.com",
}

SEARCH_DOMAINS = {
    "google": ["google.com", "google.co"],
    "bing": ["bing.com"],
    "yahoo": ["yahoo.com"],
    "duckduckgo": ["duckduckgo.com"],
    "yandex": ["yandex."],
    "baidu": ["baidu.com"],
    "ecosia": ["ecosia.org"],
}

SOCIAL_DOMAINS = {
    "pinterest": ["pinterest.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "reddit": ["reddit.com"],
    "youtube": ["youtube.com"],
    "tiktok": ["tiktok.com"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_week_bounds(week_str):
    # type: (str) -> Tuple[datetime, datetime]
    """Parse '2026-W15' into (Monday 00:00, Sunday 23:59:59)."""
    year, week = week_str.split("-W")
    # ISO week: Monday is day 1
    monday = datetime.strptime(f"{year}-W{int(week):02d}-1", "%Y-W%W-%w")
    # strptime %W is zero-indexed, ISO weeks are 1-indexed — use fromisocalendar
    monday = datetime.fromisocalendar(int(year), int(week), 1)
    sunday = monday + timedelta(days=6, hours=23, minutes=59, seconds=59)
    return monday, sunday


def last_complete_week():
    # type: () -> str
    """Return the ISO week string for the most recently completed week."""
    today = datetime.now()
    # Go back to last Sunday
    days_since_sunday = (today.weekday() + 1) % 7
    if days_since_sunday == 0:
        days_since_sunday = 7  # If today is Sunday, go to previous Sunday
    last_sunday = today - timedelta(days=days_since_sunday)
    iso = last_sunday.isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"


def classify_referrer(ref):
    # type: (str) -> Tuple[str, str]
    """Classify a referrer URL. Returns (category, source_name)."""
    if ref == "-" or ref == "":
        return ("direct", "direct")

    ref_lower = ref.lower()

    if any(d in ref_lower for d in INTERNAL_DOMAINS):
        return ("internal", "internal")

    for name, domains in SEARCH_DOMAINS.items():
        if any(d in ref_lower for d in domains):
            return ("search", name)

    for name, domains in SOCIAL_DOMAINS.items():
        if any(d in ref_lower for d in domains):
            return ("social", name)

    return ("other", ref)


def filter_week(entries, monday, sunday):
    # type: (List[LogEntry], datetime, datetime) -> List[LogEntry]
    """Filter entries to a specific week.
    Handles both timezone-aware and naive datetimes by comparing dates."""
    mon_date = monday.date()
    sun_date = sunday.date()
    return [e for e in entries if mon_date <= e.timestamp.date() <= sun_date]


def get_smtp_password():
    # type: () -> str
    """Read SMTP password from secrets file."""
    with open(SMTP_PASS_FILE, "r") as f:
        return f.read().strip()


# ---------------------------------------------------------------------------
# Report Data Builder
# ---------------------------------------------------------------------------

def build_report_data(
    all_entries,   # type: List[LogEntry]
    week_entries,  # type: List[LogEntry]
    prev_entries,  # type: List[LogEntry]
    profiles,      # type: Dict[str, IPProfile]
    target_week,   # type: str
):
    # type: (...) -> dict
    """Build all report data for the target week."""

    def split_organic(entries):
        # type: (List[LogEntry]) -> Tuple[List[LogEntry], List[LogEntry]]
        organic = []
        known = []
        for e in entries:
            p = profiles.get(e.ip)
            if p and p.role != "organic":
                known.append(e)
            else:
                organic.append(e)
        return organic, known

    week_organic, week_known = split_organic(week_entries)
    prev_organic, prev_known = split_organic(prev_entries)

    # --- Organic page views ---
    def page_views(entries):
        # type: (List[LogEntry]) -> int
        return sum(1 for e in entries
                   if e.traffic_class == "human" and e.is_page and e.status == 200)

    def unique_visitors(entries):
        # type: (List[LogEntry]) -> int
        return len(set(e.ip for e in entries if e.traffic_class == "human"))

    # --- Top pages ---
    def top_pages(entries, n=20):
        # type: (List[LogEntry], int) -> List[Tuple[str, int]]
        pages = Counter()
        for e in entries:
            if e.traffic_class == "human" and e.is_page and e.status == 200:
                path = e.path.rstrip("/") or "/"
                pages[path] += 1
        return pages.most_common(n)

    # --- Referrer breakdown ---
    def referrer_breakdown(entries):
        # type: (List[LogEntry]) -> dict
        search = Counter()
        social = Counter()
        direct = 0
        other = Counter()

        for e in entries:
            if e.traffic_class != "human" or not e.is_page or e.status != 200:
                continue
            cat, name = classify_referrer(e.referrer)
            if cat in ("direct", "internal"):
                direct += 1
            elif cat == "search":
                search[name] += 1
            elif cat == "social":
                social[name] += 1
            else:
                other[name] += 1

        return {
            "direct": direct,
            "search": dict(search.most_common()),
            "social": dict(social.most_common()),
            "other": dict(other.most_common(10)),
        }

    # --- Daily breakdown within the week ---
    def daily_breakdown(entries):
        # type: (List[LogEntry]) -> Dict[str, dict]
        days = defaultdict(lambda: {"requests": 0, "page_views": 0, "unique_ips": set()})
        for e in entries:
            day = e.timestamp.strftime("%Y-%m-%d (%a)")
            d = days[day]
            d["requests"] += 1
            if e.traffic_class == "human" and e.is_page and e.status == 200:
                d["page_views"] += 1
            if e.traffic_class == "human":
                d["unique_ips"].add(e.ip)
        return {day: {"requests": d["requests"], "page_views": d["page_views"],
                       "unique_visitors": len(d["unique_ips"])}
                for day, d in sorted(days.items())}

    # --- Non-organic breakdown ---
    def known_breakdown(entries):
        # type: (List[LogEntry]) -> dict
        by_role = defaultdict(lambda: {"requests": 0, "ips": set()})
        for e in entries:
            p = profiles.get(e.ip)
            if p and p.role != "organic":
                r = by_role[p.role]
                r["requests"] += 1
                r["ips"].add(e.ip)
        return {role: {"requests": d["requests"], "unique_ips": len(d["ips"])}
                for role, d in sorted(by_role.items(), key=lambda x: x[1]["requests"], reverse=True)}

    # --- 404s ---
    def top_404s(entries, n=15):
        # type: (List[LogEntry], int) -> List[Tuple[str, int]]
        errors = Counter()
        for e in entries:
            if e.status == 404:
                path = e.path.rstrip("/") or "/"
                errors[path] += 1
        return errors.most_common(n)

    # --- New non-organic IPs this week ---
    def new_classified_ips(week_known, prev_entries):
        # type: (List[LogEntry], List[LogEntry]) -> List[dict]
        prev_ips = set(e.ip for e in prev_entries)
        new_ips = set()
        for e in week_known:
            p = profiles.get(e.ip)
            if p and p.role != "organic" and e.ip not in prev_ips:
                new_ips.add(e.ip)
        result = []
        for ip in new_ips:
            p = profiles[ip]
            result.append({
                "ip": ip,
                "role": p.role,
                "requests": sum(1 for e in week_known if e.ip == ip),
                "reason": p.match_reason[:80] if p.match_reason else "",
            })
        result.sort(key=lambda x: x["requests"], reverse=True)
        return result[:20]

    # --- Crawler activity ---
    def crawler_summary(entries):
        # type: (List[LogEntry]) -> dict
        crawlers = Counter()
        for e in entries:
            if e.traffic_class == "search_crawler":
                ua = e.user_agent.lower()
                if "googlebot" in ua:
                    crawlers["Googlebot"] += 1
                elif "bingbot" in ua:
                    crawlers["Bingbot"] += 1
                elif "yandex" in ua:
                    crawlers["Yandex"] += 1
                elif "baidu" in ua:
                    crawlers["Baidu"] += 1
                elif "applebot" in ua:
                    crawlers["Applebot"] += 1
                elif "duckduck" in ua:
                    crawlers["DuckDuckBot"] += 1
                elif "semrush" in ua:
                    crawlers["Semrush"] += 1
                elif "ahrefs" in ua:
                    crawlers["Ahrefs"] += 1
                elif "petalbot" in ua:
                    crawlers["Petalbot"] += 1
                else:
                    crawlers["Other"] += 1
        return dict(crawlers.most_common())

    # Build it all
    week_pv = page_views(week_organic)
    prev_pv = page_views(prev_organic)
    week_uv = unique_visitors(week_organic)
    prev_uv = unique_visitors(prev_organic)

    return {
        "target_week": target_week,
        "week_requests": len(week_entries),
        "week_organic_requests": len(week_organic),
        "week_known_requests": len(week_known),
        "prev_requests": len(prev_entries),
        "prev_organic_requests": len(prev_organic),
        "week_organic_pv": week_pv,
        "prev_organic_pv": prev_pv,
        "pv_change": week_pv - prev_pv,
        "pv_change_pct": ((week_pv - prev_pv) / prev_pv * 100) if prev_pv else 0,
        "week_organic_uv": week_uv,
        "prev_organic_uv": prev_uv,
        "uv_change": week_uv - prev_uv,
        "uv_change_pct": ((week_uv - prev_uv) / prev_uv * 100) if prev_uv else 0,
        "daily": daily_breakdown(week_organic),
        "top_pages": top_pages(week_organic),
        "prev_top_pages": top_pages(prev_organic),
        "referrers": referrer_breakdown(week_organic),
        "prev_referrers": referrer_breakdown(prev_organic),
        "known_breakdown": known_breakdown(week_entries),
        "new_classified_ips": new_classified_ips(week_known, prev_entries),
        "top_404s": top_404s(week_entries),
        "crawlers": crawler_summary(week_entries),
        "prev_crawlers": crawler_summary(prev_entries),
    }


# ---------------------------------------------------------------------------
# Report Formatter
# ---------------------------------------------------------------------------

def format_report(data):
    # type: (dict) -> str
    """Format the weekly report as plain text."""
    lines = []
    w = data["target_week"]

    lines.append("=" * 72)
    lines.append("CTAI WEEKLY SEO TRAFFIC REPORT")
    lines.append("Catherine Truman Architects & Interiors")
    lines.append(f"Week: {w}")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("=" * 72)

    # --- Headline Numbers ---
    lines.append(f"\n{'─' * 60}")
    lines.append("HEADLINE NUMBERS")
    lines.append(f"{'─' * 60}")

    pv = data["week_organic_pv"]
    pv_prev = data["prev_organic_pv"]
    pv_delta = data["pv_change"]
    pv_pct = data["pv_change_pct"]
    uv = data["week_organic_uv"]
    uv_prev = data["prev_organic_uv"]
    uv_delta = data["uv_change"]
    uv_pct = data["uv_change_pct"]

    arrow_pv = "▲" if pv_delta > 0 else "▼" if pv_delta < 0 else "─"
    arrow_uv = "▲" if uv_delta > 0 else "▼" if uv_delta < 0 else "─"

    lines.append(f"  Organic Page Views:     {pv:>6,}  (prev: {pv_prev:>6,})  "
                 f"{arrow_pv} {pv_delta:+,} ({pv_pct:+.1f}%)")
    lines.append(f"  Organic Unique Visitors:{uv:>6,}  (prev: {uv_prev:>6,})  "
                 f"{arrow_uv} {uv_delta:+,} ({uv_pct:+.1f}%)")
    lines.append(f"  Total Requests:         {data['week_requests']:>6,}  "
                 f"(organic: {data['week_organic_requests']:,}, "
                 f"non-organic: {data['week_known_requests']:,})")

    # --- Daily Breakdown ---
    lines.append(f"\n{'─' * 60}")
    lines.append("DAILY BREAKDOWN (organic)")
    lines.append(f"{'─' * 60}")
    lines.append(f"  {'Day':>22}  {'PV':>6}  {'UV':>6}  {'Reqs':>7}")
    for day, d in data["daily"].items():
        bar = "█" * min(d["page_views"] // 5, 30) if d["page_views"] else ""
        lines.append(f"  {day:>22}  {d['page_views']:>6,}  "
                     f"{d['unique_visitors']:>6,}  {d['requests']:>7,}  {bar}")

    # --- Top Pages ---
    lines.append(f"\n{'─' * 60}")
    lines.append("TOP PAGES (organic page views)")
    lines.append(f"{'─' * 60}")
    prev_page_dict = dict(data["prev_top_pages"])
    lines.append(f"  {'#':>3}  {'This':>6} {'Prev':>6} {'Chg':>6}  Path")
    for i, (path, count) in enumerate(data["top_pages"][:20], 1):
        prev_count = prev_page_dict.get(path, 0)
        change = count - prev_count
        chg_str = f"{change:+d}" if prev_count > 0 else "new"
        lines.append(f"  {i:>3}. {count:>6,} {prev_count:>6,} {chg_str:>6}  {path[:55]}")

    # --- Referrer Sources ---
    lines.append(f"\n{'─' * 60}")
    lines.append("TRAFFIC SOURCES (organic page views)")
    lines.append(f"{'─' * 60}")

    ref = data["referrers"]
    prev_ref = data["prev_referrers"]

    lines.append(f"\n  Direct / Internal:  {ref['direct']:>6,}  "
                 f"(prev: {prev_ref['direct']:>6,})")

    if ref["search"]:
        lines.append(f"\n  Search Engines:")
        for engine, count in ref["search"].items():
            prev_count = prev_ref.get("search", {}).get(engine, 0)
            delta = count - prev_count
            arrow = "▲" if delta > 0 else "▼" if delta < 0 else ""
            lines.append(f"    {engine.capitalize():15s} {count:>6,}  "
                         f"(prev: {prev_count:>4,})  {arrow}{abs(delta) if delta else ''}")

    if ref["social"]:
        lines.append(f"\n  Social:")
        for platform, count in ref["social"].items():
            prev_count = prev_ref.get("social", {}).get(platform, 0)
            delta = count - prev_count
            arrow = "▲" if delta > 0 else "▼" if delta < 0 else ""
            lines.append(f"    {platform.capitalize():15s} {count:>6,}  "
                         f"(prev: {prev_count:>4,})  {arrow}{abs(delta) if delta else ''}")

    if ref["other"]:
        lines.append(f"\n  Other External Referrers:")
        for url, count in list(ref["other"].items())[:8]:
            lines.append(f"    {count:>6,}  {url[:65]}")

    # --- Search Crawler Activity ---
    lines.append(f"\n{'─' * 60}")
    lines.append("SEARCH CRAWLER ACTIVITY")
    lines.append(f"{'─' * 60}")
    if data["crawlers"]:
        for crawler, count in data["crawlers"].items():
            prev_count = data["prev_crawlers"].get(crawler, 0)
            delta = count - prev_count
            arrow = "▲" if delta > 0 else "▼" if delta < 0 else ""
            lines.append(f"  {crawler:15s} {count:>6,}  "
                         f"(prev: {prev_count:>4,})  {arrow}{abs(delta) if delta else ''}")
    else:
        lines.append("  No crawler activity detected this week.")

    # --- Non-Organic Breakdown ---
    lines.append(f"\n{'─' * 60}")
    lines.append("NON-ORGANIC TRAFFIC BREAKDOWN")
    lines.append(f"{'─' * 60}")
    all_roles = {**ROLE_DESCRIPTIONS, **EXTENDED_ROLE_DESCRIPTIONS}
    for role, d in data["known_breakdown"].items():
        desc = all_roles.get(role, role)
        lines.append(f"  {desc:35s}  {d['requests']:>7,} reqs  ({d['unique_ips']} IPs)")

    # --- New Non-Organic IPs ---
    if data["new_classified_ips"]:
        lines.append(f"\n{'─' * 60}")
        lines.append("NEW NON-ORGANIC IPs THIS WEEK")
        lines.append(f"{'─' * 60}")
        for ip_data in data["new_classified_ips"]:
            role_desc = all_roles.get(ip_data["role"], ip_data["role"])
            lines.append(f"  {ip_data['ip']:>18s}  {ip_data['requests']:>5,} reqs  "
                         f"{role_desc}")
            if ip_data["reason"]:
                lines.append(f"    → {ip_data['reason']}")

    # --- Top 404s ---
    if data["top_404s"]:
        lines.append(f"\n{'─' * 60}")
        lines.append("TOP 404 ERRORS")
        lines.append(f"{'─' * 60}")
        for path, count in data["top_404s"][:15]:
            lines.append(f"  {count:>6,}  {path[:65]}")

    lines.append(f"\n{'=' * 72}")
    lines.append("END OF WEEKLY REPORT")
    lines.append(f"{'=' * 72}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Email Sender
# ---------------------------------------------------------------------------

def send_report_email(report_text, target_week, dry_run=False):
    # type: (str, str, bool) -> bool
    """Send the report via email."""
    subject = f"CTAI Weekly SEO Report — {target_week}"

    msg = MIMEMultipart()
    msg["From"] = REPORT_FROM
    msg["To"] = REPORT_TO
    msg["Subject"] = subject

    # Plain text body
    body = f"Weekly SEO traffic report for Catherine Truman Architects.\n\n{report_text}"
    msg.attach(MIMEText(body, "plain", "utf-8"))

    if dry_run:
        print(f"\n[DRY RUN] Would send email:")
        print(f"  From: {REPORT_FROM}")
        print(f"  To: {REPORT_TO}")
        print(f"  Subject: {subject}")
        print(f"  Body length: {len(body)} chars")
        return True

    password = get_smtp_password()

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, password)
            server.send_message(msg)
        print(f"Email sent to {REPORT_TO}")
        return True
    except Exception as e:
        print(f"ERROR sending email: {e}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CTAI Weekly SEO Report")
    parser.add_argument("--week", type=str, default=None,
                        help="Target week (e.g. 2026-W15). Default: last complete week.")
    parser.add_argument("--email", action="store_true",
                        help="Send report via email to Quinn")
    parser.add_argument("--test", action="store_true",
                        help="Dry run (print email details, don't send)")
    parser.add_argument("--log-dir", type=str, default=None,
                        help="Path to access_logs directory")
    args = parser.parse_args()

    target_week = args.week or last_complete_week()
    log_dir = args.log_dir or LOG_DIR

    print(f"CTAI Weekly Report — {target_week}")
    print(f"Log directory: {log_dir}")

    # Parse all logs (need full history for classifier training)
    print("\nParsing logs...")
    all_entries = parse_all_logs(log_dir)
    print(f"Total entries: {len(all_entries):,}")

    # Classify all IPs across full dataset (behavioral needs all data)
    print("Classifying IPs...")
    profiles = classify_all(all_entries)

    # Get week bounds
    monday, sunday = get_week_bounds(target_week)
    print(f"Week: {monday.strftime('%Y-%m-%d')} (Mon) → {sunday.strftime('%Y-%m-%d')} (Sun)")

    # Get previous week bounds
    prev_monday = monday - timedelta(days=7)
    prev_sunday = monday - timedelta(seconds=1)

    # Filter entries
    week_entries = filter_week(all_entries, monday, sunday)
    prev_entries = filter_week(all_entries, prev_monday, prev_sunday)

    if not week_entries:
        print(f"\nERROR: No log entries found for week {target_week}")
        print(f"  Date range in logs: {all_entries[0].timestamp.strftime('%Y-%m-%d')} → "
              f"{all_entries[-1].timestamp.strftime('%Y-%m-%d')}")
        sys.exit(1)

    print(f"  This week: {len(week_entries):,} entries")
    print(f"  Prev week: {len(prev_entries):,} entries")

    # Build and format report
    print("\nBuilding report...")
    data = build_report_data(all_entries, week_entries, prev_entries, profiles, target_week)
    report_text = format_report(data)

    # Save report
    output_dir = os.path.dirname(__file__)
    report_path = os.path.join(output_dir, f"report_weekly_{target_week}.txt")
    with open(report_path, "w") as f:
        f.write(report_text)
    print(f"Report saved: {report_path}")

    # Save JSON too
    json_path = os.path.join(output_dir, f"report_weekly_{target_week}.json")
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"JSON saved: {json_path}")

    # Print report
    print(f"\n{report_text}")

    # Email if requested
    if args.email:
        send_report_email(report_text, target_week, dry_run=args.test)

    return 0


if __name__ == "__main__":
    sys.exit(main())
