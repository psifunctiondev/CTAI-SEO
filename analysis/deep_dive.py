"""
Deep-dive analysis for Quinn's follow-up questions:
1. Search terms from organic referrers
2. Specific social media posts as referrers
3. Admin/designer IP activity spikes
"""

import os
import sys
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs

from log_parser import parse_all_logs, LogEntry


def search_term_analysis(entries: list[LogEntry]):
    """Extract any search terms visible in referrer URLs."""
    print("=" * 60)
    print("1. SEARCH TERMS FROM ORGANIC REFERRERS")
    print("=" * 60)
    
    search_refs = []
    for e in entries:
        if e.referrer == '-' or not e.referrer:
            continue
        ref_lower = e.referrer.lower()
        if any(s in ref_lower for s in ['google.', 'bing.', 'duckduckgo.', 'yahoo.', 'ecosia.']):
            search_refs.append(e)
    
    # Try to extract query parameters
    terms_found = Counter()
    refs_with_params = []
    
    for e in search_refs:
        try:
            parsed = urlparse(e.referrer)
            params = parse_qs(parsed.query)
            # Google uses 'q', Bing uses 'q', DuckDuckGo uses 'q', Yahoo uses 'p'
            query = params.get('q', params.get('p', params.get('query', [None])))[0]
            if query:
                terms_found[query] += 1
                refs_with_params.append((query, e.path, e.referrer))
        except:
            pass
    
    if terms_found:
        print(f"\nSearch terms found in referrer URLs ({len(terms_found)} unique):")
        for term, count in terms_found.most_common(30):
            print(f"  {count:>4}x  \"{term}\"")
    else:
        print("\n  No search terms found in referrer query strings.")
    
    print(f"\n  NOTE: Since ~2011, Google encrypts search queries for logged-in users.")
    print(f"  Most referrers show just 'https://www.google.com/' with no 'q=' parameter.")
    print(f"  This is called '(not provided)' in Google Analytics.")
    
    # Show what we DO see in the referrer URLs
    print(f"\n  Referrer URL patterns from search engines:")
    ref_patterns = Counter()
    for e in search_refs:
        try:
            parsed = urlparse(e.referrer)
            # Simplify: domain + path
            pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                # Show param keys only
                params = parse_qs(parsed.query)
                param_keys = sorted(params.keys())
                pattern += f"?{'&'.join(k+'=...' for k in param_keys)}"
            ref_patterns[pattern] += 1
        except:
            ref_patterns[e.referrer] += 1
    
    for pattern, count in ref_patterns.most_common(20):
        print(f"    {count:>5}  {pattern[:100]}")
    
    # Show the Google /url redirects — some have destination info
    print(f"\n  Google /url redirect destinations (what Google linked to):")
    google_url_dests = Counter()
    for e in search_refs:
        if '/url' in e.referrer and 'google' in e.referrer.lower():
            try:
                parsed = urlparse(e.referrer)
                params = parse_qs(parsed.query)
                dest = params.get('url', params.get('q', [None]))[0]
                if dest:
                    google_url_dests[dest] += 1
            except:
                pass
    
    if google_url_dests:
        for dest, count in google_url_dests.most_common(20):
            print(f"    {count:>5}  {dest}")
    
    # Which pages do organic visitors land on?
    print(f"\n  Top landing pages from organic search (page views):")
    organic_pages = Counter()
    for e in search_refs:
        if e.is_page and e.status == 200:
            organic_pages[e.path.rstrip('/') or '/'] += 1
    for page, count in organic_pages.most_common(20):
        print(f"    {count:>5}  {page}")


def social_referrer_analysis(entries: list[LogEntry]):
    """Analyze specific social media post referrers."""
    print(f"\n{'=' * 60}")
    print("2. SOCIAL MEDIA REFERRERS — SPECIFIC POSTS")
    print("=" * 60)
    
    social_domains = {
        'pinterest.com': 'Pinterest',
        'facebook.com': 'Facebook',
        'fb.com': 'Facebook', 
        'l.facebook.com': 'Facebook',
        'lm.facebook.com': 'Facebook',
        'm.facebook.com': 'Facebook',
        'instagram.com': 'Instagram',
        'l.instagram.com': 'Instagram',
        'linkedin.com': 'LinkedIn',
        'twitter.com': 'Twitter/X',
        'x.com': 'X',
        'reddit.com': 'Reddit',
        'tiktok.com': 'TikTok',
        'youtube.com': 'YouTube',
    }
    
    social_refs = []
    for e in entries:
        if e.referrer == '-' or not e.referrer:
            continue
        ref_lower = e.referrer.lower()
        for domain in social_domains:
            if domain in ref_lower:
                social_refs.append(e)
                break
    
    # Group by platform with full referrer URL → landing page
    by_platform = defaultdict(list)
    for e in social_refs:
        ref_lower = e.referrer.lower()
        platform = 'Other'
        for domain, name in social_domains.items():
            if domain in ref_lower:
                platform = name
                break
        if e.is_page and e.status == 200:
            by_platform[platform].append(e)
    
    for platform in sorted(by_platform.keys()):
        entries_p = by_platform[platform]
        print(f"\n  --- {platform} ({len(entries_p)} page visits) ---")
        
        # Show unique referrer URLs
        ref_to_pages = defaultdict(Counter)
        for e in entries_p:
            ref_to_pages[e.referrer][e.path.rstrip('/') or '/'] += 1
        
        ref_counts = Counter()
        for ref in ref_to_pages:
            ref_counts[ref] = sum(ref_to_pages[ref].values())
        
        for ref, count in ref_counts.most_common(15):
            print(f"    {count:>4}x  {ref[:90]}")
            # Show which pages they landed on
            for page, pcount in ref_to_pages[ref].most_common(3):
                print(f"           → {page} ({pcount}x)")
    
    # Pinterest pin analysis
    print(f"\n  --- Pinterest Pin Details ---")
    pin_pages = defaultdict(Counter)
    for e in social_refs:
        if 'pinterest.com/pin/' in e.referrer and e.is_page and e.status == 200:
            pin_pages[e.referrer][e.path.rstrip('/') or '/'] += 1
    
    if pin_pages:
        print(f"  {len(pin_pages)} unique Pinterest pins drove traffic:")
        for pin, pages in sorted(pin_pages.items(), key=lambda x: sum(x[1].values()), reverse=True):
            total = sum(pages.values())
            print(f"    {total:>3}x  {pin}")
            for page, count in pages.most_common(3):
                print(f"           → {page} ({count}x)")


def admin_activity_analysis(entries: list[LogEntry]):
    """Find IPs with admin/editing activity and their traffic spikes."""
    print(f"\n{'=' * 60}")
    print("3. ADMIN / DESIGNER ACTIVITY SPIKES")
    print("=" * 60)
    
    # Find IPs that accessed wp-admin or wp-login successfully
    admin_ips = set()
    wp_admin_access = defaultdict(list)
    
    for e in entries:
        if ('/wp-admin' in e.path or '/wp-login' in e.path) and e.status in (200, 302, 301):
            admin_ips.add(e.ip)
            wp_admin_access[e.ip].append(e)
    
    print(f"\n  IPs that accessed wp-admin/wp-login (status 200/301/302): {len(admin_ips)}")
    
    # For each admin IP, show daily activity
    print(f"\n  Top admin IPs by total requests:")
    admin_ip_total = Counter()
    admin_ip_daily = defaultdict(lambda: Counter())
    
    for e in entries:
        if e.ip in admin_ips:
            admin_ip_total[e.ip] += 1
            day = e.timestamp.strftime('%Y-%m-%d')
            admin_ip_daily[e.ip][day] += 1
    
    for ip, total in admin_ip_total.most_common(20):
        admin_entries = [e for e in wp_admin_access[ip]]
        # Get a sample user agent
        uas = Counter(e.user_agent for e in admin_entries)
        top_ua = uas.most_common(1)[0][0] if uas else 'unknown'
        
        daily = admin_ip_daily[ip]
        active_days = len(daily)
        peak_day = daily.most_common(1)[0] if daily else ('?', 0)
        
        print(f"\n    IP: {ip}")
        print(f"      Total requests: {total:,}")
        print(f"      Active days: {active_days}")
        print(f"      Peak day: {peak_day[0]} ({peak_day[1]:,} requests)")
        print(f"      UA: {top_ua[:80]}")
        
        # Show daily breakdown for high-activity IPs
        if total > 500:
            print(f"      Daily activity:")
            for day, count in sorted(daily.items()):
                bar = '█' * min(count // 10, 50)
                print(f"        {day}  {count:>5}  {bar}")
    
    # Now look for single-IP spikes in overall traffic
    print(f"\n  --- Single-IP Daily Traffic Spikes (non-bot, >100 requests/day) ---")
    ip_daily = defaultdict(lambda: Counter())
    for e in entries:
        if e.traffic_class == 'human':
            day = e.timestamp.strftime('%Y-%m-%d')
            ip_daily[day][e.ip] += 1
    
    spike_days = []
    for day in sorted(ip_daily.keys()):
        top_ips = ip_daily[day].most_common(5)
        # Flag if any single IP has >100 requests (unusual for normal browsing)
        for ip, count in top_ips:
            if count > 100:
                spike_days.append((day, ip, count))
    
    if spike_days:
        print(f"  Found {len(spike_days)} spike events:")
        for day, ip, count in sorted(spike_days, key=lambda x: x[2], reverse=True)[:30]:
            is_admin = "⚡ADMIN" if ip in admin_ips else ""
            # Get their most common paths
            paths = Counter()
            for e in entries:
                if e.ip == ip and e.timestamp.strftime('%Y-%m-%d') == day and e.traffic_class == 'human':
                    paths[e.path.rstrip('/') or '/'] += 1
            top_paths = paths.most_common(3)
            path_str = ', '.join(f"{p}({c})" for p, c in top_paths)
            print(f"    {day}  {ip:>18}  {count:>5} reqs  {is_admin}  [{path_str[:60]}]")
    else:
        print("  No significant single-IP spikes found.")


if __name__ == '__main__':
    log_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), '..', 'access_logs'
    )
    
    print(f"Parsing logs from: {log_dir}")
    entries = parse_all_logs(log_dir)
    print(f"Total entries: {len(entries):,}\n")
    
    search_term_analysis(entries)
    social_referrer_analysis(entries)
    admin_activity_analysis(entries)
