"""
CTAI Traffic Analyzer

Generates SEO-relevant metrics and reports from parsed access logs.
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter
from dataclasses import asdict
from pathlib import Path

from log_parser import parse_all_logs, LogEntry


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def daily_traffic(entries: list[LogEntry]) -> dict:
    """Traffic volume by day, split by classification."""
    daily = defaultdict(lambda: defaultdict(int))
    for e in entries:
        day = e.timestamp.strftime('%Y-%m-%d')
        daily[day][e.traffic_class] += 1
        daily[day]['total'] += 1
    return dict(sorted(daily.items()))


def hourly_distribution(entries: list[LogEntry]) -> dict:
    """Request distribution by hour of day (for human traffic)."""
    humans = [e for e in entries if e.traffic_class == 'human']
    hours = Counter(e.timestamp.hour for e in humans)
    return {h: hours.get(h, 0) for h in range(24)}


def top_pages(entries: list[LogEntry], n: int = 30) -> list[dict]:
    """Top pages by human page views."""
    pages = Counter()
    for e in entries:
        if e.traffic_class == 'human' and e.is_page and e.status == 200:
            # Normalize path
            path = e.path.rstrip('/')
            if not path:
                path = '/'
            pages[path] += 1
    return [{'path': p, 'views': c} for p, c in pages.most_common(n)]


def top_entry_pages(entries: list[LogEntry], n: int = 20) -> list[dict]:
    """
    Top landing pages — first page a unique IP visits in a session.
    Approximation: first page request per IP per day.
    """
    seen = set()
    landing = Counter()
    for e in entries:
        if e.traffic_class == 'human' and e.is_page and e.status == 200:
            day = e.timestamp.strftime('%Y-%m-%d')
            key = (e.ip, day)
            if key not in seen:
                seen.add(key)
                path = e.path.rstrip('/') or '/'
                landing[path] += 1
    return [{'path': p, 'sessions': c} for p, c in landing.most_common(n)]


def referrer_analysis(entries: list[LogEntry]) -> dict:
    """Analyze referrer sources for human page traffic."""
    referrers = Counter()
    search_referrers = Counter()
    social_referrers = Counter()
    direct = 0

    search_domains = {'google.com', 'google.co', 'bing.com', 'yahoo.com',
                      'duckduckgo.com', 'yandex.', 'baidu.com', 'ecosia.org'}
    social_domains = {'facebook.com', 'fb.com', 'instagram.com', 'twitter.com',
                      'x.com', 'linkedin.com', 'pinterest.com', 'reddit.com',
                      'tiktok.com', 'youtube.com'}

    for e in entries:
        if e.traffic_class != 'human' or not e.is_page or e.status != 200:
            continue
        ref = e.referrer
        if ref == '-' or ref == '' or 'catherinetrumanarchitects.com' in ref or 'truman-architects.com' in ref:
            direct += 1
            continue

        referrers[ref] += 1

        ref_lower = ref.lower()
        is_search = any(sd in ref_lower for sd in search_domains)
        is_social = any(sd in ref_lower for sd in social_domains)

        if is_search:
            # Extract search engine name
            for sd in search_domains:
                if sd in ref_lower:
                    engine = sd.split('.')[0].capitalize()
                    search_referrers[engine] += 1
                    break
        elif is_social:
            for sd in social_domains:
                if sd in ref_lower:
                    platform = sd.split('.')[0].capitalize()
                    social_referrers[platform] += 1
                    break

    return {
        'direct_or_internal': direct,
        'search_engines': dict(search_referrers.most_common()),
        'social': dict(social_referrers.most_common()),
        'top_referrers': [{'url': r, 'count': c} for r, c in referrers.most_common(20)],
        'total_external_referrals': sum(referrers.values()),
    }


def crawler_activity(entries: list[LogEntry]) -> dict:
    """Analyze search engine crawler behavior."""
    crawlers = defaultdict(lambda: {
        'requests': 0,
        'pages_crawled': set(),
        'status_codes': Counter(),
        'first_seen': None,
        'last_seen': None,
        'daily_requests': Counter(),
    })

    for e in entries:
        if e.traffic_class != 'search_crawler':
            continue
        c = crawlers[e.crawler_name]
        c['requests'] += 1
        if e.is_page:
            c['pages_crawled'].add(e.path.rstrip('/') or '/')
        c['status_codes'][str(e.status)] += 1
        ts = e.timestamp
        if c['first_seen'] is None or ts < c['first_seen']:
            c['first_seen'] = ts
        if c['last_seen'] is None or ts > c['last_seen']:
            c['last_seen'] = ts
        c['daily_requests'][ts.strftime('%Y-%m-%d')] += 1

    # Serialize
    result = {}
    for name, data in crawlers.items():
        result[name] = {
            'total_requests': data['requests'],
            'unique_pages_crawled': len(data['pages_crawled']),
            'top_pages_crawled': Counter(
                e.path.rstrip('/') or '/' for e in entries
                if e.traffic_class == 'search_crawler' and e.crawler_name == name and e.is_page
            ).most_common(15),
            'status_codes': dict(data['status_codes'].most_common()),
            'first_seen': data['first_seen'].isoformat() if data['first_seen'] else None,
            'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None,
            'avg_daily_requests': round(
                data['requests'] / max(len(data['daily_requests']), 1), 1
            ),
        }
    return result


def error_analysis(entries: list[LogEntry]) -> dict:
    """Analyze 404s and other errors — critical for SEO."""
    errors_404 = Counter()
    errors_500 = Counter()
    status_dist = Counter()

    for e in entries:
        status_dist[e.status] += 1
        if e.status == 404:
            errors_404[e.path] += 1
        elif e.status >= 500:
            errors_500[e.path] += 1

    return {
        'status_distribution': dict(sorted(status_dist.items())),
        'top_404s': [{'path': p, 'count': c} for p, c in errors_404.most_common(30)],
        'top_500s': [{'path': p, 'count': c} for p, c in errors_500.most_common(10)],
        'total_404s': sum(errors_404.values()),
        'total_5xx': sum(errors_500.values()),
    }


def security_threats(entries: list[LogEntry]) -> dict:
    """Summarize malicious/suspicious activity."""
    malicious = [e for e in entries if e.traffic_class in ('malicious', 'suspicious')]

    attack_types = Counter(e.crawler_name for e in malicious)
    attack_ips = Counter(e.ip for e in malicious)
    attack_paths = Counter(e.path for e in malicious)

    return {
        'total_malicious': len([e for e in malicious if e.traffic_class == 'malicious']),
        'total_suspicious': len([e for e in malicious if e.traffic_class == 'suspicious']),
        'attack_types': dict(attack_types.most_common()),
        'top_attacker_ips': [{'ip': ip, 'count': c} for ip, c in attack_ips.most_common(15)],
        'top_attack_paths': [{'path': p, 'count': c} for p, c in attack_paths.most_common(15)],
    }


def unique_visitors(entries: list[LogEntry]) -> dict:
    """Daily unique visitors (human traffic only)."""
    daily_ips = defaultdict(set)
    for e in entries:
        if e.traffic_class == 'human':
            day = e.timestamp.strftime('%Y-%m-%d')
            daily_ips[day].add(e.ip)
    return {day: len(ips) for day, ips in sorted(daily_ips.items())}


def weekly_summary(entries: list[LogEntry]) -> list[dict]:
    """Weekly traffic summary for trend analysis."""
    # Group by ISO week
    weeks = defaultdict(lambda: {
        'human_requests': 0,
        'human_page_views': 0,
        'unique_ips': set(),
        'crawler_requests': 0,
        'errors_404': 0,
        'malicious': 0,
        'start_date': None,
        'end_date': None,
    })

    for e in entries:
        iso = e.timestamp.isocalendar()
        week_key = f"{iso[0]}-W{iso[1]:02d}"
        w = weeks[week_key]

        day_str = e.timestamp.strftime('%Y-%m-%d')
        if w['start_date'] is None or day_str < w['start_date']:
            w['start_date'] = day_str
        if w['end_date'] is None or day_str > w['end_date']:
            w['end_date'] = day_str

        if e.traffic_class == 'human':
            w['human_requests'] += 1
            if e.is_page and e.status == 200:
                w['human_page_views'] += 1
            w['unique_ips'].add(e.ip)
        elif e.traffic_class == 'search_crawler':
            w['crawler_requests'] += 1
        elif e.traffic_class in ('malicious', 'suspicious'):
            w['malicious'] += 1
        if e.status == 404:
            w['errors_404'] += 1

    result = []
    for week_key in sorted(weeks):
        w = weeks[week_key]
        result.append({
            'week': week_key,
            'start_date': w['start_date'],
            'end_date': w['end_date'],
            'human_requests': w['human_requests'],
            'human_page_views': w['human_page_views'],
            'unique_visitors': len(w['unique_ips']),
            'crawler_requests': w['crawler_requests'],
            'errors_404': w['errors_404'],
            'malicious_requests': w['malicious'],
        })
    return result


def hostname_analysis(entries: list[LogEntry]) -> dict:
    """Traffic split across hostnames."""
    hosts = Counter(e.hostname for e in entries)
    return dict(hosts.most_common())


def bot_vs_human_ratio(entries: list[LogEntry]) -> dict:
    """Overall bot vs human breakdown."""
    total = len(entries)
    classes = Counter(e.traffic_class for e in entries)
    human = classes.get('human', 0)
    non_human = total - human

    return {
        'total_requests': total,
        'human': human,
        'human_pct': round(human / total * 100, 1) if total else 0,
        'non_human': non_human,
        'non_human_pct': round(non_human / total * 100, 1) if total else 0,
        'breakdown': {k: v for k, v in classes.most_common()},
    }


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

def generate_report(entries: list[LogEntry]) -> dict:
    """Generate the full analysis report."""
    print("\nGenerating analysis report...")

    print("  → Traffic classification...")
    classification = bot_vs_human_ratio(entries)

    print("  → Weekly trends...")
    weekly = weekly_summary(entries)

    print("  → Unique visitors...")
    visitors = unique_visitors(entries)

    print("  → Top pages...")
    pages = top_pages(entries)

    print("  → Landing pages...")
    landing = top_entry_pages(entries)

    print("  → Referrer analysis...")
    referrers = referrer_analysis(entries)

    print("  → Crawler activity...")
    crawlers = crawler_activity(entries)

    print("  → Error analysis...")
    errors = error_analysis(entries)

    print("  → Security threats...")
    security = security_threats(entries)

    print("  → Hourly distribution...")
    hourly = hourly_distribution(entries)

    print("  → Hostname analysis...")
    hostnames = hostname_analysis(entries)

    date_range = {
        'start': entries[0].timestamp.strftime('%Y-%m-%d'),
        'end': entries[-1].timestamp.strftime('%Y-%m-%d'),
        'days': (entries[-1].timestamp - entries[0].timestamp).days + 1,
    }

    return {
        'report_generated': datetime.now().isoformat(),
        'date_range': date_range,
        'classification_summary': classification,
        'weekly_trends': weekly,
        'daily_unique_visitors': visitors,
        'top_pages': pages,
        'top_landing_pages': landing,
        'referrer_analysis': referrers,
        'crawler_activity': crawlers,
        'error_analysis': errors,
        'security_threats': security,
        'hourly_distribution': hourly,
        'hostname_distribution': hostnames,
    }


def print_text_report(report: dict) -> str:
    """Format report as readable text."""
    lines = []
    lines.append("=" * 72)
    lines.append("CTAI ACCESS LOG ANALYSIS — BASELINE REPORT")
    lines.append(f"Catherine Truman Architects & Interiors")
    lines.append(f"Period: {report['date_range']['start']} to {report['date_range']['end']} ({report['date_range']['days']} days)")
    lines.append(f"Report generated: {report['report_generated']}")
    lines.append("=" * 72)

    # --- Traffic Classification ---
    c = report['classification_summary']
    lines.append(f"\n{'─' * 40}")
    lines.append("1. TRAFFIC CLASSIFICATION")
    lines.append(f"{'─' * 40}")
    lines.append(f"Total requests:    {c['total_requests']:>10,}")
    lines.append(f"Human traffic:     {c['human']:>10,}  ({c['human_pct']}%)")
    lines.append(f"Non-human:         {c['non_human']:>10,}  ({c['non_human_pct']}%)")
    lines.append(f"\nBreakdown:")
    for cls, count in c['breakdown'].items():
        pct = count / c['total_requests'] * 100
        lines.append(f"  {cls:20s} {count:>8,}  ({pct:5.1f}%)")

    # --- Weekly Trends ---
    lines.append(f"\n{'─' * 40}")
    lines.append("2. WEEKLY TRENDS")
    lines.append(f"{'─' * 40}")
    lines.append(f"{'Week':>10} {'Dates':>25} {'PageViews':>10} {'Visitors':>10} {'Crawlers':>10} {'404s':>6}")
    for w in report['weekly_trends']:
        lines.append(
            f"{w['week']:>10} {w['start_date']}→{w['end_date']} "
            f"{w['human_page_views']:>10,} {w['unique_visitors']:>10,} "
            f"{w['crawler_requests']:>10,} {w['errors_404']:>6,}"
        )

    # --- Top Pages ---
    lines.append(f"\n{'─' * 40}")
    lines.append("3. TOP PAGES (Human Page Views)")
    lines.append(f"{'─' * 40}")
    for i, p in enumerate(report['top_pages'][:20], 1):
        lines.append(f"  {i:>3}. {p['views']:>6,}  {p['path']}")

    # --- Landing Pages ---
    lines.append(f"\n{'─' * 40}")
    lines.append("4. TOP LANDING PAGES (First page per session)")
    lines.append(f"{'─' * 40}")
    for i, p in enumerate(report['top_landing_pages'][:15], 1):
        lines.append(f"  {i:>3}. {p['sessions']:>6,}  {p['path']}")

    # --- Referrers ---
    ref = report['referrer_analysis']
    lines.append(f"\n{'─' * 40}")
    lines.append("5. REFERRER ANALYSIS")
    lines.append(f"{'─' * 40}")
    lines.append(f"Direct / internal:   {ref['direct_or_internal']:>8,}")
    lines.append(f"External referrals:  {ref['total_external_referrals']:>8,}")
    if ref['search_engines']:
        lines.append(f"\nOrganic search:")
        for engine, count in ref['search_engines'].items():
            lines.append(f"  {engine:20s} {count:>6,}")
    if ref['social']:
        lines.append(f"\nSocial:")
        for platform, count in ref['social'].items():
            lines.append(f"  {platform:20s} {count:>6,}")
    if ref['top_referrers']:
        lines.append(f"\nTop external referrers:")
        for r in ref['top_referrers'][:10]:
            lines.append(f"  {r['count']:>6,}  {r['url'][:80]}")

    # --- Crawler Activity ---
    lines.append(f"\n{'─' * 40}")
    lines.append("6. SEARCH ENGINE CRAWLER ACTIVITY")
    lines.append(f"{'─' * 40}")
    for name, data in sorted(report['crawler_activity'].items(),
                              key=lambda x: x[1]['total_requests'], reverse=True):
        lines.append(f"\n  {name}:")
        lines.append(f"    Total requests:      {data['total_requests']:>8,}")
        lines.append(f"    Unique pages found:  {data['unique_pages_crawled']:>8,}")
        lines.append(f"    Avg daily requests:  {data['avg_daily_requests']:>8}")
        lines.append(f"    Status codes:        {data['status_codes']}")
        if data['top_pages_crawled']:
            lines.append(f"    Top pages crawled:")
            for path, count in data['top_pages_crawled'][:5]:
                lines.append(f"      {count:>5,}  {path}")

    # --- Errors ---
    err = report['error_analysis']
    lines.append(f"\n{'─' * 40}")
    lines.append("7. ERROR ANALYSIS (SEO Impact)")
    lines.append(f"{'─' * 40}")
    lines.append(f"Total 404s: {err['total_404s']:,}")
    lines.append(f"Total 5xx:  {err['total_5xx']:,}")
    lines.append(f"\nStatus code distribution:")
    for code, count in sorted(err['status_distribution'].items()):
        lines.append(f"  {code:>5}  {count:>8,}")
    if err['top_404s']:
        lines.append(f"\nTop 404 URLs (broken links — SEO priority!):")
        for e in err['top_404s'][:15]:
            lines.append(f"  {e['count']:>6,}  {e['path'][:80]}")

    # --- Security ---
    sec = report['security_threats']
    lines.append(f"\n{'─' * 40}")
    lines.append("8. SECURITY THREATS")
    lines.append(f"{'─' * 40}")
    lines.append(f"Malicious requests:   {sec['total_malicious']:>8,}")
    lines.append(f"Suspicious requests:  {sec['total_suspicious']:>8,}")
    if sec['attack_types']:
        lines.append(f"\nAttack types:")
        for atype, count in sec['attack_types'].items():
            lines.append(f"  {atype:25s} {count:>6,}")
    if sec['top_attacker_ips']:
        lines.append(f"\nTop attacker IPs:")
        for a in sec['top_attacker_ips'][:10]:
            lines.append(f"  {a['count']:>6,}  {a['ip']}")

    # --- Hourly Distribution ---
    lines.append(f"\n{'─' * 40}")
    lines.append("9. HOURLY TRAFFIC DISTRIBUTION (Human)")
    lines.append(f"{'─' * 40}")
    hourly = report['hourly_distribution']
    max_h = max(hourly.values()) if hourly else 1
    for h in range(24):
        count = hourly.get(str(h), hourly.get(h, 0))
        bar = '█' * int(count / max_h * 40) if max_h > 0 else ''
        lines.append(f"  {h:02d}:00  {count:>6,}  {bar}")

    # --- Hostnames ---
    lines.append(f"\n{'─' * 40}")
    lines.append("10. HOSTNAME DISTRIBUTION")
    lines.append(f"{'─' * 40}")
    for host, count in report['hostname_distribution'].items():
        lines.append(f"  {host:45s} {count:>8,}")

    lines.append(f"\n{'=' * 72}")
    lines.append("END OF REPORT")
    lines.append(f"{'=' * 72}")

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    log_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), '..', 'access_logs'
    )

    print(f"Parsing logs from: {log_dir}")
    entries = parse_all_logs(log_dir)
    print(f"\nTotal entries parsed: {len(entries):,}")

    report = generate_report(entries)

    # Save JSON report
    output_dir = os.path.dirname(__file__)
    json_path = os.path.join(output_dir, 'report_baseline.json')
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nJSON report saved: {json_path}")

    # Save text report
    text_report = print_text_report(report)
    text_path = os.path.join(output_dir, 'report_baseline.txt')
    with open(text_path, 'w') as f:
        f.write(text_report)
    print(f"Text report saved: {text_path}")

    # Also print to stdout
    print(f"\n{text_report}")
