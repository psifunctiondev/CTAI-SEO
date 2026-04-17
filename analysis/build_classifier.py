"""
Analyze behavioral patterns of known IPs to build classifier rules.
This is a one-time analysis script to inform the classifier design.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from log_parser import parse_all_logs
from known_ips import KNOWN_IPS
from collections import defaultdict, Counter

entries = parse_all_logs(os.path.join(os.path.dirname(__file__), "..", "access_logs"))

# Group entries by IP
by_ip = defaultdict(list)
for e in entries:
    by_ip[e.ip].append(e)

def analyze_ip(ip, entries):
    """Extract behavioral features from an IP's request history."""
    days = set()
    paths = Counter()
    uas = Counter()
    statuses = Counter()
    methods = Counter()
    hourly = Counter()
    wp_admin_count = 0
    wp_admin_200 = 0
    divi_builder = 0
    wp_login = 0
    attack_paths = 0
    page_views = 0

    attack_signatures = {
        '/.well-known/index.php', '/manager.php', '/bless.php',
        '/O-Simple.php', '/lock360.php', '/wp-content/themes/pridmag/db.php',
        '/.env', '/.aws/credentials', '/phpinfo.php',
        '/vendor/phpunit', '/wp-includes/Requests/about.php'
    }

    for e in entries:
        days.add(e.timestamp.strftime("%Y-%m-%d"))
        paths[e.path] += 1
        uas[e.user_agent[:80]] += 1
        statuses[e.status] += 1
        methods[e.method] += 1
        hourly[e.timestamp.hour] += 1
        if e.is_page and e.status == 200:
            page_views += 1
        if '/wp-admin' in e.path:
            wp_admin_count += 1
            if e.status == 200:
                wp_admin_200 += 1
        if '/wp-login' in e.path:
            wp_login += 1
        if 'et_fb=1' in e.path or 'et_bfb=1' in e.path:
            divi_builder += 1
        for sig in attack_signatures:
            if sig in e.path:
                attack_paths += 1
                break

    active_days = len(days)
    total = len(entries)
    daily_avg = total / max(active_days, 1)

    # Steadiness: coefficient of variation of daily counts
    daily_counts = Counter()
    for e in entries:
        daily_counts[e.timestamp.strftime("%Y-%m-%d")] += 1
    counts = list(daily_counts.values())
    if len(counts) > 1:
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        cv = (variance ** 0.5) / mean if mean > 0 else 0
    else:
        cv = 0

    return {
        'total': total,
        'active_days': active_days,
        'daily_avg': daily_avg,
        'cv': cv,
        'wp_admin_count': wp_admin_count,
        'wp_admin_200': wp_admin_200,
        'wp_admin_rate': wp_admin_count / total if total > 0 else 0,
        'divi_builder': divi_builder,
        'wp_login': wp_login,
        'attack_paths': attack_paths,
        'attack_rate': attack_paths / total if total > 0 else 0,
        'page_views': page_views,
        'top_ua': uas.most_common(1)[0] if uas else ('', 0),
        'top_paths': paths.most_common(5),
        'unique_paths': len(paths),
        'statuses': dict(statuses.most_common(5)),
    }

# Analyze known IPs
print("=" * 70)
print("BEHAVIORAL FEATURES OF KNOWN IPS")
print("=" * 70)

for role in ['admin_designer', 'admin_content', 'hosting', 'scanner']:
    print(f"\n{'---' * 20}")
    print(f"ROLE: {role}")
    print(f"{'---' * 20}")
    for ip, info in KNOWN_IPS.items():
        if info.role != role:
            continue
        if ip not in by_ip:
            continue
        f = analyze_ip(ip, by_ip[ip])
        print(f"\n  {ip} ({info.label})")
        print(f"    Requests: {f['total']:,}  Active days: {f['active_days']}  Daily avg: {f['daily_avg']:.0f}")
        print(f"    CV (steadiness): {f['cv']:.2f}  (lower = steadier)")
        print(f"    wp-admin: {f['wp_admin_count']:,} ({f['wp_admin_rate']:.1%})  wp-admin 200/302: {f['wp_admin_200']:,}")
        print(f"    Divi Builder: {f['divi_builder']:,}  wp-login: {f['wp_login']:,}")
        print(f"    Attack paths: {f['attack_paths']:,} ({f['attack_rate']:.1%})")
        print(f"    Unique paths: {f['unique_paths']:,}  Page views: {f['page_views']:,}")
        print(f"    Top UA: {f['top_ua'][0][:70]}")

# Find UNKNOWN IPs matching admin patterns
print(f"\n{'=' * 70}")
print("UNKNOWN IPS MATCHING ADMIN PATTERNS (>20 wp-admin with 200/302)")
print("=" * 70)

for ip, elist in sorted(by_ip.items(), key=lambda x: len(x[1]), reverse=True):
    if ip in KNOWN_IPS:
        continue
    f = analyze_ip(ip, elist)
    if f['wp_admin_200'] > 20:
        print(f"\n  {ip} -- {f['total']:,} requests, {f['active_days']} days")
        print(f"    wp-admin 200/302: {f['wp_admin_200']:,}  Divi: {f['divi_builder']}  wp-login: {f['wp_login']}")
        print(f"    Top UA: {f['top_ua'][0][:70]}")
        print(f"    Top paths: {[p[0][:40] for p in f['top_paths'][:3]]}")

print(f"\n{'=' * 70}")
print("UNKNOWN IPS MATCHING HOSTING PATTERN (CV < 0.3, >20 active days)")
print("=" * 70)

for ip, elist in sorted(by_ip.items(), key=lambda x: len(x[1]), reverse=True):
    if ip in KNOWN_IPS:
        continue
    f = analyze_ip(ip, elist)
    if f['cv'] < 0.3 and f['active_days'] > 20 and f['total'] > 200:
        print(f"\n  {ip} -- {f['total']:,} requests, {f['active_days']} days, CV={f['cv']:.2f}")
        print(f"    Daily avg: {f['daily_avg']:.1f}  Top UA: {f['top_ua'][0][:70]}")

print(f"\n{'=' * 70}")
print("UNKNOWN IPS MATCHING SCANNER PATTERN (>10% attack paths, >100 reqs)")
print("=" * 70)

for ip, elist in sorted(by_ip.items(), key=lambda x: len(x[1]), reverse=True):
    if ip in KNOWN_IPS:
        continue
    f = analyze_ip(ip, elist)
    if f['attack_rate'] > 0.10 and f['total'] > 100:
        print(f"\n  {ip} -- {f['total']:,} requests, attack rate: {f['attack_rate']:.1%}")
        print(f"    Top paths: {[p[0][:50] for p in f['top_paths'][:3]]}")
