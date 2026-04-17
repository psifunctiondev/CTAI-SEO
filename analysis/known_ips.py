"""
Known IP Registry for CTAI Traffic Analysis

Tags IPs with known roles so reports can show both the full picture
and the organic-only view. IPs are flagged, never removed.

Categories:
  - admin_designer: Web design team (Divi Builder activity, heavy wp-admin)
  - admin_content:  Content maintenance team (regular wp-admin, steady edits)
  - hosting:        Hosting infrastructure (server cron, monitoring, self-requests)
  - scanner:        Vulnerability scanners posing as legitimate traffic
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class KnownIP:
    ip: str
    role: str           # admin_designer, admin_content, hosting, scanner
    label: str          # Human-readable label
    evidence: str       # Why we flagged this IP
    confidence: str     # high, medium, low


# ---------------------------------------------------------------------------
# Known IP database — derived from access log analysis (Jan 5 – Mar 4, 2026)
# ---------------------------------------------------------------------------

KNOWN_IPS: dict[str, KnownIP] = {

    # --- Web Designer / SEO Team ---
    "163.252.150.0": KnownIP(
        ip="163.252.150.0",
        role="admin_designer",
        label="Web Designer (primary)",
        evidence=(
            "14,137 requests over 17 days (peak 3,316 on Feb 2). "
            "Mac/Firefox user. Divi Builder activity (?et_fb=1&et_bfb=1). "
            "Heavy wp-admin/wp-login access with 200/302 responses."
        ),
        confidence="high",
    ),
    "158.41.240.0": KnownIP(
        ip="158.41.240.0",
        role="admin_designer",
        label="Web Designer (secondary)",
        evidence=(
            "3,983 requests over 4 days (peak 2,020 on Feb 7). "
            "Mac/Firefox user. Heavy Divi Builder + about-us page editing. "
            "Burst pattern matches design work sessions."
        ),
        confidence="high",
    ),

    # --- Content Maintenance ---
    "148.76.189.0": KnownIP(
        ip="148.76.189.0",
        role="admin_content",
        label="Content Manager",
        evidence=(
            "6,935 requests over 48 active days. Windows/Chrome user. "
            "Consistent daily presence with periodic editing spikes "
            "(peak 997 on Feb 19). Pattern matches regular content updates."
        ),
        confidence="high",
    ),

    # --- Hosting Infrastructure ---
    "74.208.59.0": KnownIP(
        ip="74.208.59.0",
        role="hosting",
        label="Hosting Server (cron/monitoring)",
        evidence=(
            "3,431 requests over all 59 days. Perfectly steady ~55-60/day. "
            "WordPress self-pings (wp-cron.php), internal monitoring. "
            "IP belongs to 1&1/IONOS hosting infrastructure."
        ),
        confidence="high",
    ),

    # --- Vulnerability Scanners (classified as human by UA but attack patterns) ---
    "194.5.82.0": KnownIP(
        ip="194.5.82.0",
        role="scanner",
        label="Vulnerability Scanner A",
        evidence=(
            "8,981 requests over 12 days (peak 1,785 on Feb 25). "
            "Probing /wp-includes/ID3, /vendor/phpunit, /manager.php, "
            "/bless.php. Windows/Chrome UA but attack-pattern paths."
        ),
        confidence="high",
    ),
    "193.37.32.0": KnownIP(
        ip="193.37.32.0",
        role="scanner",
        label="Vulnerability Scanner B",
        evidence=(
            "6,645 requests over 11 days (peak 1,525 on Feb 27). "
            "Probing /.well-known/index.php, /manager.php, /bless.php, "
            "/O-Simple.php. Windows/Firefox UA but attack-pattern paths."
        ),
        confidence="high",
    ),
    "194.61.40.0": KnownIP(
        ip="194.61.40.0",
        role="scanner",
        label="Vulnerability Scanner C",
        evidence=(
            "4,563 requests over 5 days (peak 2,308 on Feb 2). "
            "Probing /.well-known/index.php, /wp-includes/ID3, /manager.php. "
            "Burst scan pattern."
        ),
        confidence="high",
    ),
    "212.30.36.0": KnownIP(
        ip="212.30.36.0",
        role="scanner",
        label="Vulnerability Scanner D",
        evidence=(
            "3,464 requests — 3,462 on single day (Jan 25). "
            "Probing /.well-known/index.php, /wp-includes/ID3, /manager.php. "
            "Single massive burst scan."
        ),
        confidence="high",
    ),
    "103.163.220.0": KnownIP(
        ip="103.163.220.0",
        role="scanner",
        label="Vulnerability Scanner E",
        evidence=(
            "4,179 requests over 3 days (peak 3,024 on Feb 10). "
            "Probing /wp-content/uploads, /wp-content/plugins, /wp-includes. "
            "Directory enumeration pattern."
        ),
        confidence="high",
    ),
    "212.30.33.0": KnownIP(
        ip="212.30.33.0",
        role="scanner",
        label="Vulnerability Scanner F",
        evidence=(
            "2,442 requests over 3 days (peak 2,308 on Feb 21). "
            "Same attack patterns as 212.30.36.0 — likely same operator. "
            "/.well-known/index.php, /manager.php probes."
        ),
        confidence="high",
    ),
    "185.177.72.0": KnownIP(
        ip="185.177.72.0",
        role="scanner",
        label="Curl Scanner",
        evidence=(
            "4,368 requests over 6 days (peak 1,665 on Mar 3). "
            "UA is 'curl/8.7.1'. Automated scanning tool."
        ),
        confidence="high",
    ),
    "85.203.15.0": KnownIP(
        ip="85.203.15.0",
        role="scanner",
        label="Vulnerability Scanner G",
        evidence=(
            "2,223 requests over 5 days. Short UA ('Mozilla/5.0'). "
            "Probing /.well-known/index.php, /wp-includes/ID3, /manager.php."
        ),
        confidence="high",
    ),
    "85.203.21.0": KnownIP(
        ip="85.203.21.0",
        role="scanner",
        label="Vulnerability Scanner H (same /16 as G)",
        evidence=(
            "1,781 requests over 3 days. Same 85.203.x.x range. "
            "Same attack patterns."
        ),
        confidence="high",
    ),
    "45.132.224.0": KnownIP(
        ip="45.132.224.0",
        role="scanner",
        label="Vulnerability Scanner I",
        evidence=(
            "2,188 requests over 3 days (peak 1,072 on Feb 15). "
            "Burst scanning pattern."
        ),
        confidence="high",
    ),
    "103.125.146.0": KnownIP(
        ip="103.125.146.0",
        role="scanner",
        label="Vulnerability Scanner J",
        evidence=(
            "~1,057 requests on Feb 18. Probing /wp-includes/Requests/about.php, "
            "/wp-content/themes/ enumeration."
        ),
        confidence="medium",
    ),
    "185.221.132.0": KnownIP(
        ip="185.221.132.0",
        role="scanner",
        label="Vulnerability Scanner K",
        evidence=(
            "~909 requests on Feb 7. /.well-known/index.php, /manager.php probes."
        ),
        confidence="medium",
    ),

    # --- Recurring bot classified as human (sitemap crawlers) ---
    "202.8.43.0": KnownIP(
        ip="202.8.43.0",
        role="scanner",
        label="Sitemap Crawler (weekly)",
        evidence=(
            "~1,453 requests/week, every Sunday for 5 weeks. "
            "Hits /sitemap_index.xml, /robots.txt, then crawls entire site. "
            "Automated, not organic."
        ),
        confidence="high",
    ),
    "168.100.149.0": KnownIP(
        ip="168.100.149.0",
        role="scanner",
        label="Sitemap Crawler (weekly, replaced 202.8.43.0)",
        evidence=(
            "Same ~1,450 requests/week pattern starting Feb 9. "
            "Took over from 202.8.43.0. Same crawl signature."
        ),
        confidence="high",
    ),
}


def get_known_ip(ip: str) -> Optional[KnownIP]:
    """Look up an IP in the known registry."""
    return KNOWN_IPS.get(ip)


def get_role_for_ip(ip: str) -> str:
    """Return the role tag for a known IP, or 'organic' if unknown."""
    known = KNOWN_IPS.get(ip)
    return known.role if known else "organic"


def get_label_for_ip(ip: str) -> str:
    """Return a human-readable label for a known IP."""
    known = KNOWN_IPS.get(ip)
    return known.label if known else ""


# Summary helpers
ROLE_DESCRIPTIONS = {
    "admin_designer": "Web Design / SEO Team",
    "admin_content": "Content Maintenance Team",
    "hosting": "Hosting Infrastructure",
    "scanner": "Vulnerability Scanners / Bots",
    "organic": "Organic Traffic (real visitors)",
}


def summarize_registry():
    """Print the known IP registry for documentation."""
    print(f"{'=' * 70}")
    print("KNOWN IP REGISTRY — CTAI Traffic Analysis")
    print(f"{'=' * 70}")
    
    by_role = {}
    for ip, info in KNOWN_IPS.items():
        by_role.setdefault(info.role, []).append(info)
    
    for role, description in ROLE_DESCRIPTIONS.items():
        if role not in by_role:
            continue
        print(f"\n  {description}")
        print(f"  {'─' * 50}")
        for info in by_role[role]:
            print(f"    {info.ip:>18}  {info.label}")
            print(f"    {'':>18}  Confidence: {info.confidence}")
            print(f"    {'':>18}  {info.evidence[:100]}")
            print()


if __name__ == "__main__":
    summarize_registry()
    print(f"\nTotal known IPs: {len(KNOWN_IPS)}")
    by_role = {}
    for info in KNOWN_IPS.values():
        by_role.setdefault(info.role, []).append(info)
    for role, infos in by_role.items():
        print(f"  {role}: {len(infos)}")
