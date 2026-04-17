"""
CTAI Behavioral IP Classifier

Classifies IPs by behavior patterns rather than hardcoded addresses.
Works across log periods even when IPs change.

Classification hierarchy (first match wins):
  1. Known IP registry match (known_ips.py) — highest confidence
  2. Behavioral rules based on request patterns

Behavioral roles:
  - admin_designer: Divi Builder activity, heavy wp-admin with 200s, Mac/Firefox
  - admin_content:  Regular wp-admin with 200s, multi-day presence, no Divi
  - hosting:        Very steady daily rate (low CV), WordPress UA, 30+ days
  - wp_recon:       WP reconnaissance bots — hit wp-login, get 302 back from
                    wp-admin (not authenticated), enumerate ?author= IDs
  - scanner:        Known attack path probing, curl UA, brute force
  - sitemap_bot:    Hits sitemap_index.xml first, then crawls full site, weekly
  - organic:        Everything else

Key insight: wp-admin 200 = actually authenticated (real admin).
wp-admin 301+302 with 0 200s = unauthenticated redirect loop (bot).
The site is publicly accessible but WordPress still returns 302 for
unauthenticated wp-admin requests.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Optional

from known_ips import KNOWN_IPS, get_role_for_ip, ROLE_DESCRIPTIONS


@dataclass
class IPProfile:
    """Behavioral profile for a single IP address."""
    ip: str
    total_requests: int = 0
    active_days: int = 0
    first_seen: str = ""
    last_seen: str = ""
    page_views: int = 0

    # wp-admin behavior
    wp_admin_count: int = 0
    wp_admin_200: int = 0      # wp-admin requests with HTTP 200 (actually authenticated)
    wp_admin_302: int = 0      # wp-admin requests with 301/302 (unauthenticated redirect)
    wp_login_count: int = 0
    wp_login_200: int = 0      # wp-login page renders (200)
    wp_login_503: int = 0      # wp-login rate-limited (503)
    author_enum: int = 0       # ?author=N user enumeration requests
    divi_builder: int = 0      # requests with ?et_fb=1 or ?et_bfb=1

    # Attack indicators
    attack_paths: int = 0

    # Steadiness (coefficient of variation of daily request counts)
    cv: float = 0.0

    # Sitemap indicators
    sitemap_hits: int = 0
    robots_hits: int = 0

    # UA info
    top_ua: str = ""
    is_wordpress_ua: bool = False
    is_curl_ua: bool = False

    # Unique paths (high ratio = scanning)
    unique_paths: int = 0

    # Classification result
    role: str = "organic"
    confidence: str = "n/a"
    match_source: str = ""     # "registry" or "behavioral"
    match_reason: str = ""


# Attack path signatures used for scanner detection
ATTACK_SIGNATURES = frozenset({
    '/.well-known/index.php', '/manager.php', '/bless.php',
    '/O-Simple.php', '/lock360.php',
    '/.env', '/.aws/credentials', '/phpinfo.php',
    '/vendor/phpunit', '/wp-includes/Requests/about.php',
    '/wp-content/themes/pridmag/db.php',
})


def build_ip_profiles(entries) -> dict:
    """
    Build behavioral profiles for every IP from log entries.
    
    Args:
        entries: List of LogEntry objects from log_parser.parse_all_logs()
    
    Returns:
        Dict mapping IP -> IPProfile
    """
    # Group by IP
    by_ip = defaultdict(list)
    for e in entries:
        by_ip[e.ip].append(e)

    profiles = {}
    for ip, ip_entries in by_ip.items():
        p = IPProfile(ip=ip)
        p.total_requests = len(ip_entries)

        days = set()
        daily_counts = Counter()
        paths = set()
        uas = Counter()

        for e in ip_entries:
            day = e.timestamp.strftime("%Y-%m-%d")
            days.add(day)
            daily_counts[day] += 1
            paths.add(e.path)
            uas[e.user_agent[:100]] += 1

            if e.is_page and e.status == 200:
                p.page_views += 1

            path = e.path
            if '/wp-admin' in path:
                p.wp_admin_count += 1
                if e.status == 200:
                    p.wp_admin_200 += 1
                elif e.status in (301, 302):
                    p.wp_admin_302 += 1
            if '/wp-login' in path:
                p.wp_login_count += 1
                if e.status == 200:
                    p.wp_login_200 += 1
                elif e.status == 503:
                    p.wp_login_503 += 1
            if '?author=' in path:
                p.author_enum += 1
            if 'et_fb=1' in path or 'et_bfb=1' in path:
                p.divi_builder += 1
            if '/sitemap' in path.lower():
                p.sitemap_hits += 1
            if '/robots.txt' in path:
                p.robots_hits += 1

            for sig in ATTACK_SIGNATURES:
                if sig in path:
                    p.attack_paths += 1
                    break

        sorted_days = sorted(days)
        p.active_days = len(days)
        p.first_seen = sorted_days[0] if sorted_days else ""
        p.last_seen = sorted_days[-1] if sorted_days else ""
        p.unique_paths = len(paths)

        # Coefficient of variation
        counts = list(daily_counts.values())
        if len(counts) > 1:
            mean = sum(counts) / len(counts)
            variance = sum((c - mean) ** 2 for c in counts) / len(counts)
            p.cv = (variance ** 0.5) / mean if mean > 0 else 0
        else:
            p.cv = 0.0

        # Top UA
        if uas:
            top = uas.most_common(1)[0][0]
            p.top_ua = top
            p.is_wordpress_ua = 'WordPress/' in top
            p.is_curl_ua = top.startswith('curl/')

        profiles[ip] = p

    return profiles


def classify_ip(p: IPProfile) -> IPProfile:
    """
    Classify a single IP profile. Modifies in place and returns it.
    
    Classification rules are ordered by specificity — first match wins.
    """
    # Rule 0: Known IP registry (highest priority)
    known = KNOWN_IPS.get(p.ip)
    if known:
        p.role = known.role
        p.confidence = known.confidence
        p.match_source = "registry"
        p.match_reason = known.label
        return p

    # Rule 1: Divi Builder user → admin_designer
    # The Divi ?et_fb=1 param is specific to CTAI's Elegant Themes setup.
    # Combined with actual wp-admin 200s, this is the designer.
    if p.divi_builder >= 3 and p.wp_admin_200 > 50:
        p.role = "admin_designer"
        p.confidence = "high"
        p.match_source = "behavioral"
        p.match_reason = (
            f"Divi Builder activity ({p.divi_builder} requests) + "
            f"authenticated wp-admin ({p.wp_admin_200} HTTP 200s)"
        )
        return p

    # Rule 2: WordPress reconnaissance bot
    # Signature: hits wp-login (gets 200 page render or 503 rate limit),
    # then tries wp-admin pages (gets 301/302 redirects, zero 200s).
    # Often includes ?author=N user enumeration.
    # Real admins get HTTP 200 on wp-admin. Bots never do.
    if (p.wp_login_count > 20
            and p.wp_admin_302 > 20
            and p.wp_admin_200 == 0):
        reason_parts = [f"wp-login ({p.wp_login_count} hits)"]
        reason_parts.append(
            f"wp-admin 0 authenticated, {p.wp_admin_302} redirected")
        if p.author_enum > 0:
            reason_parts.append(f"user enum (?author=N: {p.author_enum})")
        p.role = "wp_recon"
        p.confidence = "high"
        p.match_source = "behavioral"
        p.match_reason = "WP recon bot: " + ", ".join(reason_parts)
        return p

    # Rule 3: Curl scanner
    if p.is_curl_ua and p.total_requests > 50:
        p.role = "scanner"
        p.confidence = "high"
        p.match_source = "behavioral"
        p.match_reason = f"curl user-agent with {p.total_requests} requests"
        return p

    # Rule 4: Attack path scanner
    if p.attack_paths > 5 and p.total_requests > 100:
        attack_rate = p.attack_paths / p.total_requests
        if attack_rate > 0.005:  # >0.5% attack paths
            p.role = "scanner"
            p.confidence = "high" if attack_rate > 0.01 else "medium"
            p.match_source = "behavioral"
            p.match_reason = (
                f"{p.attack_paths} attack-path probes ({attack_rate:.1%} of requests)"
            )
            return p

    # Rule 5: Sitemap bot
    # Weekly pattern, hits sitemap_index.xml + robots.txt, then crawls entire site
    if (p.sitemap_hits >= 3
            and p.robots_hits >= 3
            and p.total_requests > 500
            and p.wp_admin_count == 0):
        avg_per_day = p.total_requests / max(p.active_days, 1)
        if avg_per_day > 400:
            p.role = "sitemap_bot"
            p.confidence = "high"
            p.match_source = "behavioral"
            p.match_reason = (
                f"Sitemap-first crawl pattern ({p.sitemap_hits} sitemap + "
                f"{p.robots_hits} robots.txt hits, {avg_per_day:.0f} req/active-day)"
            )
            return p

    # Rule 6: Hosting/infrastructure
    # Very steady daily rate, active 30+ days, often WordPress UA
    if p.active_days >= 30 and p.cv < 0.30 and p.total_requests > 200:
        p.role = "hosting"
        p.confidence = "high" if p.is_wordpress_ua else "medium"
        p.match_source = "behavioral"
        p.match_reason = (
            f"Steady pattern (CV={p.cv:.2f}) over {p.active_days} days, "
            f"avg {p.total_requests/p.active_days:.0f}/day"
        )
        return p

    # Rule 7: Authenticated admin (non-designer)
    # Actual wp-admin 200s over multiple days = real authenticated user
    if (p.wp_admin_200 > 30
            and p.active_days >= 5
            and p.attack_paths == 0
            and p.divi_builder == 0):
        p.role = "admin_content"
        p.confidence = "medium"
        p.match_source = "behavioral"
        p.match_reason = (
            f"Authenticated wp-admin ({p.wp_admin_200} HTTP 200s) "
            f"over {p.active_days} days, no attack paths"
        )
        return p

    # Rule 8: Brute force / login probing (no admin success)
    # Many login attempts but zero wp-admin 200s
    if p.wp_login_count > 50 and p.wp_admin_200 == 0:
        p.role = "scanner"
        p.confidence = "medium"
        p.match_source = "behavioral"
        p.match_reason = (
            f"Login probing: {p.wp_login_count} wp-login attempts, "
            f"zero authenticated wp-admin access"
        )
        return p

    # Default: organic
    p.role = "organic"
    p.confidence = "n/a"
    p.match_source = "default"
    p.match_reason = "No non-organic pattern detected"
    return p


def classify_all(entries) -> dict:
    """
    Build profiles and classify all IPs.
    
    Returns dict mapping IP -> classified IPProfile.
    """
    profiles = build_ip_profiles(entries)
    for p in profiles.values():
        classify_ip(p)
    return profiles


# Extended role descriptions including behavioral-only roles
EXTENDED_ROLE_DESCRIPTIONS = {
    **ROLE_DESCRIPTIONS,
    "wp_recon": "WordPress Reconnaissance Bots",
    "sitemap_bot": "Automated Sitemap Crawlers",
}


def summarize_classifications(profiles: dict) -> dict:
    """Aggregate classification results."""
    by_role = defaultdict(lambda: {
        "count": 0,
        "ips": [],
        "total_requests": 0,
        "page_views": 0,
        "registry_matches": 0,
        "behavioral_matches": 0,
    })

    for ip, p in profiles.items():
        r = by_role[p.role]
        r["count"] += 1
        r["total_requests"] += p.total_requests
        r["page_views"] += p.page_views
        if p.match_source == "registry":
            r["registry_matches"] += 1
        elif p.match_source == "behavioral":
            r["behavioral_matches"] += 1
        if p.role != "organic":
            r["ips"].append({
                "ip": ip,
                "requests": p.total_requests,
                "days": p.active_days,
                "source": p.match_source,
                "confidence": p.confidence,
                "reason": p.match_reason,
            })

    # Sort IPs within each role by request count
    for r in by_role.values():
        r["ips"].sort(key=lambda x: x["requests"], reverse=True)

    return dict(by_role)


# ---------------------------------------------------------------------------
# Main — run as standalone to test classifier against current logs
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys, os, json
    sys.path.insert(0, os.path.dirname(__file__))
    from log_parser import parse_all_logs

    log_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "..", "access_logs"
    )

    print(f"Parsing logs from: {log_dir}")
    entries = parse_all_logs(log_dir)
    print(f"Total entries: {len(entries):,}")

    print("\nClassifying IPs...")
    profiles = classify_all(entries)
    summary = summarize_classifications(profiles)

    # Print summary
    total_filtered = 0
    total_filtered_reqs = 0
    print(f"\n{'=' * 70}")
    print("BEHAVIORAL CLASSIFICATION RESULTS")
    print(f"{'=' * 70}")

    for role in ['admin_designer', 'admin_content', 'hosting',
                 'wp_recon', 'scanner', 'sitemap_bot', 'organic']:
        s = summary.get(role)
        if not s:
            continue
        desc = EXTENDED_ROLE_DESCRIPTIONS.get(role, role)
        reg = s['registry_matches']
        beh = s['behavioral_matches']
        print(f"\n  {desc}:")
        print(f"    IPs: {s['count']:,}  Requests: {s['total_requests']:,}  "
              f"Page views: {s['page_views']:,}")
        print(f"    Matched by: registry={reg}, behavioral={beh}, "
              f"default={s['count'] - reg - beh}")

        if role != 'organic':
            total_filtered += s['count']
            total_filtered_reqs += s['total_requests']

        # Show top IPs for non-organic roles
        if role != 'organic' and s['ips']:
            for entry in s['ips'][:10]:
                src_tag = "[R]" if entry['source'] == 'registry' else "[B]"
                print(f"      {src_tag} {entry['ip']:>18}  {entry['requests']:>6,} reqs  "
                      f"{entry['days']:>3}d  {entry['confidence']:>6}  {entry['reason'][:55]}")
            if len(s['ips']) > 10:
                print(f"      ... and {len(s['ips']) - 10} more")

    organic = summary.get('organic', {})
    print(f"\n{'=' * 70}")
    print(f"SUMMARY")
    print(f"  Total IPs analyzed:       {len(profiles):,}")
    print(f"  Non-organic IPs:          {total_filtered:,}  "
          f"({total_filtered_reqs:,} requests)")
    print(f"  Organic IPs:              {organic.get('count', 0):,}  "
          f"({organic.get('total_requests', 0):,} requests)")
    print(f"  Non-organic request share: "
          f"{total_filtered_reqs/len(entries)*100:.1f}%")
    print(f"{'=' * 70}")
