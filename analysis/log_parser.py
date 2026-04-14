"""
CTAI Access Log Parser & Traffic Classifier

Parses Apache/Nginx combined-format access logs (with hostname field)
and classifies traffic into categories useful for SEO analysis.

Log format:
  IP - - [timestamp] "METHOD /path HTTP/x.x" status bytes hostname "referrer" "user-agent" "extra"
"""

import re
import gzip
import os
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, Generator
from pathlib import Path
from collections import defaultdict, Counter


# ---------------------------------------------------------------------------
# Log line data model
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    bytes_sent: int
    hostname: str
    referrer: str
    user_agent: str
    extra: str
    # Derived fields
    traffic_class: str = ""         # human, search_crawler, seo_tool, bot, malicious, internal
    crawler_name: str = ""          # e.g., Googlebot, bingbot, AhrefsBot
    is_asset: bool = False          # CSS, JS, images, fonts
    is_page: bool = False           # HTML page request
    content_type: str = ""          # page, asset, api, other


# ---------------------------------------------------------------------------
# Regex for parsing the log format
# ---------------------------------------------------------------------------

# Format: IP - - [timestamp] "request" status bytes hostname "referrer" "user-agent" "extra"
LOG_PATTERN = re.compile(
    r'^(?P<ip>[\da-fA-F.:]+)\s+'       # IP (IPv4 or IPv6)
    r'(?P<ident>\S+)\s+'               # ident
    r'(?P<user>\S+)\s+'                # user
    r'\[(?P<timestamp>[^\]]+)\]\s+'    # [timestamp]
    r'"(?P<request>[^"]*)"\s+'         # "request line"
    r'(?P<status>\d{3})\s+'            # status code
    r'(?P<bytes>\S+)\s+'               # bytes (or -)
    r'(?P<hostname>\S+)\s+'            # hostname
    r'"(?P<referrer>[^"]*)"\s+'        # "referrer"
    r'"(?P<user_agent>[^"]*)"\s*'      # "user-agent"
    r'"?(?P<extra>[^"]*)"?'            # "extra" (optional)
)


# ---------------------------------------------------------------------------
# Traffic classification rules
# ---------------------------------------------------------------------------

# Search engine crawlers
SEARCH_CRAWLERS = {
    'googlebot': 'Googlebot',
    'google-inspectiontool': 'Google-InspectionTool',
    'google-safety': 'Google-Safety',
    'googleother': 'GoogleOther',
    'google-extended': 'Google-Extended',
    'apis-google': 'APIs-Google',
    'mediapartners-google': 'Mediapartners-Google',
    'adsbot-google': 'AdsBot-Google',
    'bingbot': 'Bingbot',
    'msnbot': 'MSNBot',
    'bingpreview': 'BingPreview',
    'yandexbot': 'YandexBot',
    'baiduspider': 'Baiduspider',
    'duckduckbot': 'DuckDuckBot',
    'slurp': 'Yahoo-Slurp',
    'applebot': 'Applebot',
    'petalbot': 'PetalBot',
}

# SEO/marketing tools
SEO_TOOLS = {
    'ahrefsbot': 'AhrefsBot',
    'semrushbot': 'SemrushBot',
    'mj12bot': 'MJ12Bot/Majestic',
    'dotbot': 'DotBot/Moz',
    'rogerbot': 'Rogerbot/Moz',
    'screaming frog': 'Screaming Frog',
    'seokicks': 'SEOkicks',
    'serpstatbot': 'SerpstatBot',
    'blexbot': 'BLEXBot',
    'dataforseo': 'DataForSEO',
}

# Known bots (non-search, non-SEO)
KNOWN_BOTS = {
    'grammarly': 'Grammarly',
    'bitsightbot': 'BitSightBot',
    'python-httpx': 'python-httpx',
    'python-requests': 'python-requests',
    'python-urllib': 'python-urllib',
    'curl': 'curl',
    'wget': 'wget',
    'go-http-client': 'Go-HTTP-Client',
    'java/': 'Java',
    'apache-httpclient': 'Apache-HttpClient',
    'headlesschrome': 'HeadlessChrome',
    'phantomjs': 'PhantomJS',
    'facebookexternalhit': 'Facebook',
    'facebot': 'Facebot',
    'twitterbot': 'TwitterBot',
    'linkedinbot': 'LinkedInBot',
    'slackbot': 'SlackBot',
    'whatsapp': 'WhatsApp',
    'telegrambot': 'TelegramBot',
    'discordbot': 'DiscordBot',
    'pinterestbot': 'PinterestBot',
    'uptimerobot': 'UptimeRobot',
    'statuscake': 'StatusCake',
    'pingdom': 'Pingdom',
    'site24x7': 'Site24x7',
    'nessus': 'Nessus',
    'nikto': 'Nikto',
    'masscan': 'Masscan',
    'zgrab': 'ZGrab',
    'censys': 'Censys',
    'shodan': 'Shodan',
    'netcraft': 'Netcraft',
    'wp-cron': 'WP-Cron',
    'wordpress': 'WordPress',
    'jetpack': 'Jetpack',
    'cookiebot': 'Cookiebot',
    'gptbot': 'GPTBot',
    'chatgpt-user': 'ChatGPT-User',
    'claudebot': 'ClaudeBot',
    'anthropic-ai': 'Anthropic-AI',
    'bytespider': 'ByteSpider',
    'claudeweb': 'ClaudeWeb',
    'ccbot': 'CCBot',
    'ia_archiver': 'Alexa/IA',
    'archive.org_bot': 'Archive.org',
}

# Malicious request patterns
MALICIOUS_PATHS = [
    r'/wp-login\.php',
    r'/wp-admin',
    r'/xmlrpc\.php',
    r'/wp-load\.php\?',
    r'\.env',
    r'/\.git',
    r'/phpmyadmin',
    r'/admin',
    r'/shell',
    r'/eval',
    r'/exec',
    r'/cmd',
    r'\.sql',
    r'/config\.',
    r'/backup',
    r'/cgi-bin',
    r'/\.well-known/security',
]
MALICIOUS_PATTERN = re.compile('|'.join(MALICIOUS_PATHS), re.IGNORECASE)

# Asset extensions
ASSET_EXTENSIONS = {
    '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.map', '.min.js', '.min.css',
    '.mp4', '.webm', '.mp3', '.ogg',
    '.pdf', '.zip', '.gz',
}

# WordPress internal paths (wp-cron, wp-json, xmlrpc, etc.)
WP_INTERNAL_PATHS = [
    r'^/wp-cron\.php',
    r'^/wp-json/',
    r'^/wp-admin/admin-ajax\.php',
]
WP_INTERNAL_PATTERN = re.compile('|'.join(WP_INTERNAL_PATHS))


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_timestamp(ts_str: str) -> datetime:
    """Parse Apache log timestamp: 05/Jan/2026:00:03:04 -0500"""
    return datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S %z')


def parse_request(request_str: str) -> tuple[str, str, str]:
    """Parse 'METHOD /path HTTP/x.x' into (method, path, protocol)."""
    parts = request_str.split(' ', 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    elif len(parts) == 2:
        return parts[0], parts[1], ''
    else:
        return '', request_str, ''


def get_path_extension(path: str) -> str:
    """Extract file extension from URL path, ignoring query strings."""
    clean = path.split('?')[0].split('#')[0]
    dot_pos = clean.rfind('.')
    if dot_pos > 0:
        return clean[dot_pos:].lower()
    return ''


def classify_content_type(path: str) -> str:
    """Classify the request path into content type."""
    ext = get_path_extension(path)
    if ext in ASSET_EXTENSIONS:
        return 'asset'
    if path.startswith('/wp-json/') or path.startswith('/wp-admin/admin-ajax'):
        return 'api'
    if WP_INTERNAL_PATTERN.match(path):
        return 'internal'
    # Pages: no extension, or .html/.htm/.php (but not wp-login etc.)
    if ext in ('', '.html', '.htm', '.php'):
        return 'page'
    return 'other'


def classify_traffic(entry: LogEntry) -> None:
    """Classify an entry into traffic categories. Mutates entry in place."""
    ua_lower = entry.user_agent.lower()

    # 1. Search engine crawlers
    for pattern, name in SEARCH_CRAWLERS.items():
        if pattern in ua_lower:
            entry.traffic_class = 'search_crawler'
            entry.crawler_name = name
            break

    # 2. SEO tools
    if not entry.traffic_class:
        for pattern, name in SEO_TOOLS.items():
            if pattern in ua_lower:
                entry.traffic_class = 'seo_tool'
                entry.crawler_name = name
                break

    # 3. Known bots
    if not entry.traffic_class:
        for pattern, name in KNOWN_BOTS.items():
            if pattern in ua_lower:
                entry.traffic_class = 'bot'
                entry.crawler_name = name
                break

    # 4. Malicious probes (check path + method patterns)
    if not entry.traffic_class:
        if MALICIOUS_PATTERN.search(entry.path):
            # wp-login POST from non-crawler is almost certainly brute force
            if entry.path.startswith('/wp-login') and entry.method == 'POST':
                entry.traffic_class = 'malicious'
                entry.crawler_name = 'brute_force'
            elif entry.path.startswith('/wp-login') and entry.method == 'GET':
                # Could be legit admin, flag as suspicious
                entry.traffic_class = 'suspicious'
                entry.crawler_name = 'wp_login_probe'
            elif '/xmlrpc.php' in entry.path:
                entry.traffic_class = 'malicious'
                entry.crawler_name = 'xmlrpc_probe'
            elif '?' in entry.path and entry.path.startswith('/wp-load'):
                entry.traffic_class = 'malicious'
                entry.crawler_name = 'wp_exploit'
            else:
                entry.traffic_class = 'suspicious'
                entry.crawler_name = 'probe'

    # 5. Empty or suspicious user agents
    if not entry.traffic_class:
        if entry.user_agent == '-' or entry.user_agent == '' or len(entry.user_agent) < 10:
            entry.traffic_class = 'bot'
            entry.crawler_name = 'empty_ua'

    # 6. WordPress internal traffic
    if not entry.traffic_class:
        if WP_INTERNAL_PATTERN.match(entry.path):
            entry.traffic_class = 'internal'
            entry.crawler_name = 'wordpress'

    # 7. If nothing matched, classify as human
    if not entry.traffic_class:
        entry.traffic_class = 'human'

    # Content type classification
    entry.content_type = classify_content_type(entry.path)
    entry.is_asset = (entry.content_type == 'asset')
    entry.is_page = (entry.content_type == 'page')


def parse_line(line: str) -> Optional[LogEntry]:
    """Parse a single log line into a LogEntry, or None if unparseable."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    d = match.groupdict()
    method, path, protocol = parse_request(d['request'])
    bytes_sent = int(d['bytes']) if d['bytes'] != '-' else 0

    try:
        timestamp = parse_timestamp(d['timestamp'])
    except ValueError:
        return None

    entry = LogEntry(
        ip=d['ip'],
        timestamp=timestamp,
        method=method,
        path=path,
        protocol=protocol,
        status=int(d['status']),
        bytes_sent=bytes_sent,
        hostname=d['hostname'],
        referrer=d['referrer'],
        user_agent=d['user_agent'],
        extra=d.get('extra', ''),
    )
    classify_traffic(entry)
    return entry


def parse_file(filepath: str) -> Generator[LogEntry, None, None]:
    """Parse a log file (plain or gzipped) yielding LogEntry objects."""
    open_fn = gzip.open if filepath.endswith('.gz') else open
    with open_fn(filepath, 'rt', encoding='utf-8', errors='replace') as f:
        for line in f:
            entry = parse_line(line)
            if entry:
                yield entry


def parse_all_logs(log_dir: str) -> list[LogEntry]:
    """Parse all log files in directory, sorted by timestamp."""
    entries = []
    log_dir = Path(log_dir)

    # Find all log files (skip .current if it's a duplicate of another)
    files = sorted([
        f for f in log_dir.iterdir()
        if f.name.startswith('access.log') and f.name != 'access.log.current'
    ])

    for filepath in files:
        count = 0
        for entry in parse_file(str(filepath)):
            entries.append(entry)
            count += 1
        print(f"  Parsed {filepath.name}: {count:,} entries")

    entries.sort(key=lambda e: e.timestamp)
    return entries


# ---------------------------------------------------------------------------
# Entry point for testing
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    log_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'access_logs')
    print(f"Parsing logs from: {log_dir}")
    entries = parse_all_logs(log_dir)
    print(f"\nTotal entries: {len(entries):,}")
    print(f"Date range: {entries[0].timestamp.strftime('%Y-%m-%d')} to {entries[-1].timestamp.strftime('%Y-%m-%d')}")

    # Quick classification summary
    class_counts = Counter(e.traffic_class for e in entries)
    print(f"\nTraffic classification:")
    for cls, count in class_counts.most_common():
        pct = count / len(entries) * 100
        print(f"  {cls:20s} {count:>8,}  ({pct:.1f}%)")
