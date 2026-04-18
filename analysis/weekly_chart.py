#!/usr/bin/env python3
"""
CTAI Weekly Visual Report — Bar Chart + Donut Breakdowns

Generates a crisp, unadorned PNG chart for Catherine's team:
- Stacked bar chart: 8 weeks, human traffic positive, mechanical negative
- Y-axis: Unique Visitors (first-touch attribution per IP per day)
- Positive buckets: Search Engine, Social Media, Direct & Other
- Referrer spam excluded from organic counts
- Negative buckets: Security Risk Scanners, Benign Scanners, WP Recon,
                    Designers, Content, Hosting, Search Crawlers
- Two donut charts (latest week): search engine & social media by site
- Psi Function branding: Michroma + IBM Plex Sans fonts, logo
"""

import os
import sys
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.font_manager as fm
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
from PIL import Image
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))

from log_parser import parse_all_logs, LogEntry
from ip_classifier import classify_all, IPProfile
from referrer_spam import is_referrer_spam, get_referrer_domain

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "access_logs")
ASSETS_DIR = os.path.join(os.path.dirname(__file__), "..", "assets")
FONTS_DIR = os.path.join(ASSETS_DIR, "fonts")

INTERNAL_DOMAINS = {
    "catherinetrumanarchitects.com",
    "truman-architects.com",
    "trumanarchitects.com",
    "www.catherinetrumanarchitects.com",
    "www.truman-architects.com",
    "www.trumanarchitects.com",
}

SEARCH_DOMAINS = {
    "Google": ["google.com", "google.co"],
    "Bing": ["bing.com"],
    "Yahoo": ["yahoo.com"],
    "DuckDuckGo": ["duckduckgo.com"],
    "Yandex": ["yandex."],
    "Baidu": ["baidu.com"],
    "Ecosia": ["ecosia.org"],
}

SOCIAL_DOMAINS = {
    "Pinterest": ["pinterest.com"],
    "Facebook": ["facebook.com", "fb.com"],
    "Instagram": ["instagram.com"],
    "LinkedIn": ["linkedin.com"],
    "Twitter/X": ["twitter.com", "x.com"],
    "Reddit": ["reddit.com"],
    "YouTube": ["youtube.com"],
    "TikTok": ["tiktok.com"],
}

# Color palette — crisp, professional, high contrast
COLOR_SEARCH = "#2563EB"          # Strong blue
COLOR_SOCIAL = "#7C3AED"          # Purple
COLOR_DIRECT = "#6B7280"          # Gray

COLOR_RISK_SCANNER = "#DC2626"    # Bright red
COLOR_BENIGN_SCANNER = "#F97316"  # Orange
COLOR_WP_RECON = "#EAB308"        # Yellow
COLOR_DESIGNER = "#22C55E"        # Green
COLOR_CONTENT = "#06B6D4"         # Cyan
COLOR_HOSTING = "#8B5CF6"         # Violet
COLOR_CRAWLERS = "#94A3B8"        # Slate gray
COLOR_REF_SPAM = "#A855F7"        # Purple (distinct from orange scanners)


# ---------------------------------------------------------------------------
# Font setup
# ---------------------------------------------------------------------------

def setup_fonts():
    """Register custom fonts and return font properties."""
    michroma_path = os.path.join(FONTS_DIR, "Michroma-Regular.ttf")
    plex_regular = os.path.join(FONTS_DIR, "IBMPlexSans-Regular.ttf")
    plex_semibold = os.path.join(FONTS_DIR, "IBMPlexSans-SemiBold.ttf")
    plex_bold = os.path.join(FONTS_DIR, "IBMPlexSans-Bold.ttf")

    fonts = {}
    for path in [michroma_path, plex_regular, plex_semibold, plex_bold]:
        if os.path.exists(path):
            fm.fontManager.addfont(path)

    # Create font properties
    if os.path.exists(michroma_path):
        fonts["title"] = fm.FontProperties(fname=michroma_path)
    else:
        fonts["title"] = fm.FontProperties(family="sans-serif", weight="bold")

    if os.path.exists(plex_regular):
        fonts["body"] = fm.FontProperties(fname=plex_regular)
        fonts["body_bold"] = fm.FontProperties(
            fname=plex_bold if os.path.exists(plex_bold) else plex_regular,
            weight="bold"
        )
        fonts["body_semi"] = fm.FontProperties(
            fname=plex_semibold if os.path.exists(plex_semibold) else plex_regular,
            weight="semibold"
        )
    else:
        fonts["body"] = fm.FontProperties(family="sans-serif")
        fonts["body_bold"] = fm.FontProperties(family="sans-serif", weight="bold")
        fonts["body_semi"] = fm.FontProperties(family="sans-serif", weight="semibold")

    return fonts


# ---------------------------------------------------------------------------
# Data extraction
# ---------------------------------------------------------------------------

def get_week_key(dt):
    # type: (datetime) -> str
    iso = dt.isocalendar()
    return "{}-W{:02d}".format(iso[0], iso[1])


def get_week_label(week_str):
    # type: (str) -> str
    year, week = week_str.split("-W")
    monday = datetime.fromisocalendar(int(year), int(week), 1)
    sunday = monday + timedelta(days=6)
    return "{} - {}".format(monday.strftime("%m/%d"), sunday.strftime("%m/%d"))


def classify_referrer(ref):
    # type: (str) -> Tuple[str, str]
    if ref == "-" or ref == "":
        return ("direct", "direct")
    ref_lower = ref.lower()
    # Extract domain for internal check
    import re
    m = re.match(r'https?://([^/]+)', ref_lower)
    if m:
        domain = m.group(1)
        if domain in INTERNAL_DOMAINS:
            return ("internal", "internal")
    for name, domains in SEARCH_DOMAINS.items():
        if any(d in ref_lower for d in domains):
            return ("search", name)
    for name, domains in SOCIAL_DOMAINS.items():
        if any(d in ref_lower for d in domains):
            return ("social", name)
    return ("other", ref)


def is_security_risk(entry, profile):
    # type: (LogEntry, Optional[IPProfile]) -> bool
    if not profile:
        return False
    attack_ratio = profile.attack_paths / max(profile.total_requests, 1)
    if attack_ratio > 0.003:
        return True
    if profile.wp_login_count > 20 and profile.wp_admin_200 == 0:
        return True
    ua = (profile.top_ua or "").lower()
    if any(t in ua for t in ['nikto', 'sqlmap', 'nmap', 'masscan', 'zgrab']):
        return True
    return False


def build_weekly_data(entries, profiles):
    # type: (List[LogEntry], Dict[str, IPProfile]) -> Dict[str, dict]
    """Build per-week unique visitor data using first-touch attribution.

    For organic human traffic: each IP is attributed ONCE per day to
    its first external referrer source. Internal site navigation
    (same-domain referrers) and referrer spam are excluded.
    This approximates session-based source attribution.

    Non-organic traffic: unique IPs per day (all hits count).
    """
    import re as _re

    # --- Pass 1: Sort entries by time for first-touch ordering ---
    sorted_entries = sorted(entries, key=lambda e: e.timestamp)

    # Track first-touch per (day, ip) for organic human traffic
    # first_touch[(day, ip)] = (bucket, search_name, social_name)
    first_touch = {}  # type: Dict[Tuple[str, str], Tuple[str, Optional[str], Optional[str]]]

    # Mechanical traffic: standard unique IP per day
    week_day_ip_bucket = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    for e in sorted_entries:
        if not e.is_page or e.status != 200:
            continue

        day = e.timestamp.strftime("%Y-%m-%d")
        p = profiles.get(e.ip)
        role = p.role if p else "organic"
        wk = get_week_key(e.timestamp)

        # --- Non-organic traffic: count all unique IPs per day ---
        if role != "organic":
            if role in ("scanner", "brute_force"):
                if is_security_risk(e, p):
                    week_day_ip_bucket[wk]["risk_scanner"][day].add(e.ip)
                else:
                    week_day_ip_bucket[wk]["benign_scanner"][day].add(e.ip)
            elif role == "wp_recon":
                week_day_ip_bucket[wk]["wp_recon"][day].add(e.ip)
            elif role == "admin_designer":
                week_day_ip_bucket[wk]["designer"][day].add(e.ip)
            elif role == "admin_content":
                week_day_ip_bucket[wk]["content"][day].add(e.ip)
            elif role == "hosting":
                week_day_ip_bucket[wk]["hosting"][day].add(e.ip)
            else:
                week_day_ip_bucket[wk]["benign_scanner"][day].add(e.ip)
            continue

        # --- Organic traffic ---
        if e.traffic_class == "search_crawler":
            week_day_ip_bucket[wk]["crawlers"][day].add(e.ip)
            continue

        if e.traffic_class != "human":
            week_day_ip_bucket[wk]["benign_scanner"][day].add(e.ip)
            continue

        # Skip referrer spam entirely
        if is_referrer_spam(e.referrer):
            week_day_ip_bucket[wk]["ref_spam"][day].add(e.ip)
            continue

        # First-touch attribution: only the FIRST page view per IP per day
        ft_key = (day, e.ip)
        if ft_key in first_touch:
            continue  # Already attributed this IP today

        # Classify referrer
        cat, name = classify_referrer(e.referrer)

        # Skip internal site navigation — wait for a real entry referrer
        if cat in ("internal",):
            continue

        # Record first touch
        search_name = name if cat == "search" else None
        social_name = name if cat == "social" else None

        if cat == "search":
            bucket = "search"
        elif cat == "social":
            bucket = "social"
        else:
            bucket = "direct_other"  # "direct", "other", or external referral

        first_touch[ft_key] = (bucket, search_name, social_name)

    # --- Pass 2: Aggregate first-touch into weekly buckets ---
    week_ft_bucket = defaultdict(lambda: defaultdict(set))  # week -> bucket -> set of (day, ip)
    week_ft_search = defaultdict(lambda: defaultdict(set))  # week -> engine -> set of (day, ip)
    week_ft_social = defaultdict(lambda: defaultdict(set))  # week -> platform -> set of (day, ip)

    for (day, ip), (bucket, sname, soname) in first_touch.items():
        # Parse day to get week
        dt = datetime.strptime(day, "%Y-%m-%d")
        wk = get_week_key(dt)
        week_ft_bucket[wk][bucket].add((day, ip))
        if sname:
            week_ft_search[wk][sname].add((day, ip))
        if soname:
            week_ft_social[wk][soname].add((day, ip))

    # --- Pass 3: Build final weekly data ---
    def sum_daily_uv(day_ip_sets):
        # type: (Dict[str, set]) -> int
        return sum(len(ips) for ips in day_ip_sets.values())

    all_weeks = set(list(week_day_ip_bucket.keys()) + list(week_ft_bucket.keys()))
    weeks_data = {}

    mechanical_buckets = ["risk_scanner", "benign_scanner", "wp_recon",
                          "designer", "content", "hosting", "crawlers",
                          "ref_spam"]

    for wk in all_weeks:
        data = {}

        # Organic (first-touch): count of (day, ip) pairs
        for bucket in ["search", "social", "direct_other"]:
            data[bucket] = len(week_ft_bucket.get(wk, {}).get(bucket, set()))

        # Mechanical: sum of daily unique IPs
        for bucket in mechanical_buckets:
            data[bucket] = sum_daily_uv(week_day_ip_bucket.get(wk, {}).get(bucket, {}))

        # Search engine detail
        data["search_detail"] = Counter()
        for name, pairs in week_ft_search.get(wk, {}).items():
            data["search_detail"][name] = len(pairs)

        # Social detail
        data["social_detail"] = Counter()
        for name, pairs in week_ft_social.get(wk, {}).items():
            data["social_detail"][name] = len(pairs)

        weeks_data[wk] = data

    return weeks_data


def get_recent_weeks(weekly_data, n=8):
    # type: (Dict[str, dict], int) -> List[str]
    all_weeks = sorted(weekly_data.keys())
    return all_weeks[-n:]


# ---------------------------------------------------------------------------
# Chart rendering
# ---------------------------------------------------------------------------

def render_chart(weekly_data, weeks, output_path, fonts):
    # type: (Dict[str, dict], List[str], str, dict) -> None

    n = len(weeks)
    latest = weeks[-1]
    latest_data = weekly_data[latest]

    # --- Figure layout ---
    fig = plt.figure(figsize=(16, 9), dpi=150, facecolor="white")

    # GridSpec: main chart left, donuts right
    gs = fig.add_gridspec(2, 2, width_ratios=[2.4, 1],
                          height_ratios=[1, 1],
                          wspace=0.3, hspace=0.35,
                          left=0.07, right=0.95, top=0.88, bottom=0.08)

    ax_bar = fig.add_subplot(gs[0:2, 0])
    ax_donut_search = fig.add_subplot(gs[0, 1])
    ax_donut_social = fig.add_subplot(gs[1, 1])

    # --- Bar chart data ---
    x = np.arange(n)
    bar_width = 0.65

    pos_direct = [weekly_data[w]["direct_other"] for w in weeks]
    pos_social = [weekly_data[w]["social"] for w in weeks]
    pos_search = [weekly_data[w]["search"] for w in weeks]

    neg_crawlers = [-weekly_data[w]["crawlers"] for w in weeks]
    neg_hosting = [-weekly_data[w]["hosting"] for w in weeks]
    neg_content = [-weekly_data[w]["content"] for w in weeks]
    neg_designer = [-weekly_data[w]["designer"] for w in weeks]
    neg_wp_recon = [-weekly_data[w]["wp_recon"] for w in weeks]
    neg_benign = [-weekly_data[w]["benign_scanner"] for w in weeks]
    neg_risk = [-weekly_data[w]["risk_scanner"] for w in weeks]
    neg_ref_spam = [-weekly_data[w].get("ref_spam", 0) for w in weeks]

    # Positive bars
    ax_bar.bar(x, pos_direct, bar_width, label="Direct & Other",
               color=COLOR_DIRECT, edgecolor="white", linewidth=0.5)
    ax_bar.bar(x, pos_social, bar_width, bottom=pos_direct,
               label="Social Media", color=COLOR_SOCIAL,
               edgecolor="white", linewidth=0.5)
    bottom_search = [d + s for d, s in zip(pos_direct, pos_social)]
    ax_bar.bar(x, pos_search, bar_width, bottom=bottom_search,
               label="Search Engine", color=COLOR_SEARCH,
               edgecolor="white", linewidth=0.5)

    # Negative bars
    neg_bottom = [0] * n
    neg_layers = [
        (neg_crawlers, "Search Crawlers", COLOR_CRAWLERS),
        (neg_hosting, "Hosting", COLOR_HOSTING),
        (neg_content, "Content", COLOR_CONTENT),
        (neg_designer, "Designers", COLOR_DESIGNER),
        (neg_ref_spam, "Referrer Spam", COLOR_REF_SPAM),
        (neg_wp_recon, "WP Recon", COLOR_WP_RECON),
        (neg_benign, "Benign Scanners", COLOR_BENIGN_SCANNER),
        (neg_risk, "Security Risk", COLOR_RISK_SCANNER),
    ]

    for values, label, color in neg_layers:
        ax_bar.bar(x, values, bar_width, bottom=neg_bottom,
                   label=label, color=color, edgecolor="white", linewidth=0.5)
        neg_bottom = [b + v for b, v in zip(neg_bottom, values)]

    # --- Axis formatting ---
    labels = [get_week_label(w) for w in weeks]
    ax_bar.set_xticks(x)
    ax_bar.set_xticklabels(labels, fontproperties=fonts["body"], fontsize=8)
    ax_bar.set_ylabel("Unique Daily Visitors Per Week",
                      fontproperties=fonts["body_semi"], fontsize=10)

    max_pos = max(d + s + se for d, s, se in zip(pos_direct, pos_social, pos_search))
    max_neg = abs(min(neg_bottom))
    y_max = max(max_pos, 50) * 1.10
    y_min = -max(max_neg, 25) * 1.15
    ax_bar.set_ylim(y_min, y_max)

    # Smart grid spacing
    full_range = y_max - y_min
    if full_range > 2000:
        major = 500
        minor = 100
    elif full_range > 1000:
        major = 250
        minor = 50
    elif full_range > 500:
        major = 100
        minor = 50
    elif full_range > 200:
        major = 50
        minor = 10
    else:
        major = 25
        minor = 5

    ax_bar.yaxis.set_major_locator(ticker.MultipleLocator(major))
    ax_bar.yaxis.set_minor_locator(ticker.MultipleLocator(minor))

    # Y-axis tick labels: absolute values with comma formatting
    ax_bar.yaxis.set_major_formatter(
        ticker.FuncFormatter(lambda val, pos: "{:,.0f}".format(abs(val)))
    )
    for label in ax_bar.yaxis.get_ticklabels():
        label.set_fontproperties(fonts["body"])
        label.set_fontsize(8)

    ax_bar.grid(axis="y", which="major", linewidth=0.8, color="#D1D5DB", alpha=0.7)
    ax_bar.grid(axis="y", which="minor", linewidth=0.3, color="#E5E7EB", alpha=0.5)

    # Bold line at zero
    ax_bar.axhline(y=0, color="#1F2937", linewidth=1.2)

    # Remove ALL spines (no border around chart)
    for spine in ax_bar.spines.values():
        spine.set_visible(False)

    # Mark partial week
    today = datetime.now()
    latest_iso = today.isocalendar()
    latest_week_str = "{}-W{:02d}".format(latest_iso[0], latest_iso[1])
    if weeks[-1] == latest_week_str:
        dow = today.strftime("%A")
        current_labels = [t.get_text() for t in ax_bar.get_xticklabels()]
        current_labels[-1] = current_labels[-1] + "*"
        ax_bar.set_xticklabels(current_labels, fontproperties=fonts["body"], fontsize=8)
        ax_bar.text(0.99, -0.06, "* partial week (through {})".format(dow),
                    transform=ax_bar.transAxes, fontsize=6.5, color="#6B7280",
                    ha="right", style="italic", fontproperties=fonts["body"])

    # --- Grouped legend using text annotations ---
    # Remove auto-generated legend
    handles, labels_legend = ax_bar.get_legend_handles_labels()
    if ax_bar.legend_:
        ax_bar.legend_.remove()

    # Human: first 3, Mechanical: rest
    human_handles = handles[:3]
    human_labels = labels_legend[:3]
    mech_handles = handles[3:]
    mech_labels = labels_legend[3:]

    from matplotlib.patches import Patch

    # Place "Human Traffic" header + items as first row
    # Place "Mechanical Traffic" header + items as second row
    # Use a single legend with invisible spacer between groups
    combined_handles = []
    combined_labels = []

    # Row 1: Human Traffic header + 3 items + spacer to fill
    combined_handles.append(Patch(facecolor="none", edgecolor="none"))
    combined_labels.append(r"$\mathbf{Human\ Traffic:}$")
    for h, l in zip(human_handles, human_labels):
        combined_handles.append(h)
        combined_labels.append(l)
    # Pad to ncol items
    combined_handles.append(Patch(facecolor="none", edgecolor="none"))
    combined_labels.append("")

    # Row 2: Mechanical Traffic header + first 4 items
    combined_handles.append(Patch(facecolor="none", edgecolor="none"))
    combined_labels.append(r"$\mathbf{Mechanical\ Traffic:}$")
    for h, l in zip(mech_handles[:4], mech_labels[:4]):
        combined_handles.append(h)
        combined_labels.append(l)

    # Row 3: remaining mechanical items, padded
    combined_handles.append(Patch(facecolor="none", edgecolor="none"))
    combined_labels.append("")
    for h, l in zip(mech_handles[4:], mech_labels[4:]):
        combined_handles.append(h)
        combined_labels.append(l)
    # Pad remaining slots
    remainder = 5 - len(mech_handles[4:])
    for _ in range(remainder):
        combined_handles.append(Patch(facecolor="none", edgecolor="none"))
        combined_labels.append("")

    leg = ax_bar.legend(
        combined_handles, combined_labels,
        loc="upper center", bbox_to_anchor=(0.5, -0.08),
        ncol=5, fontsize=6.5, frameon=False,
        columnspacing=1.4, handletextpad=0.4,
        prop=fonts["body"]
    )
    leg.set_zorder(10)

    # --- Donut charts ---
    def draw_donut(ax, data_counter, title, colors_list):
        # type: (plt.Axes, Counter, str, List[str]) -> None
        if not data_counter or sum(data_counter.values()) == 0:
            ax.text(0.5, 0.5, "No data", ha="center", va="center",
                    fontsize=10, color="#9CA3AF", transform=ax.transAxes,
                    fontproperties=fonts["body"])
            ax.set_title(title, fontproperties=fonts["body_semi"],
                         fontsize=9, pad=8)
            ax.set_aspect("equal")
            return

        items = data_counter.most_common()
        labels_d = [item[0] for item in items]
        sizes = [item[1] for item in items]
        total = sum(sizes)
        colors = colors_list[:len(items)]

        wedges, _ = ax.pie(
            sizes, labels=None, colors=colors,
            startangle=90, counterclock=False,
            wedgeprops=dict(width=0.45, edgecolor="white", linewidth=1.5),
        )

        # Build legend labels with count and percentage
        label_lines = []
        for lbl, sz in zip(labels_d, sizes):
            pct = sz / total * 100
            label_lines.append("{}: {} ({:.0f}%)".format(lbl, sz, pct))

        # Legend to the RIGHT of the donut
        ax.legend(wedges, label_lines, loc="center left",
                  bbox_to_anchor=(1.05, 0.5), fontsize=7,
                  frameon=False, handlelength=0.8, handletextpad=0.4,
                  labelspacing=0.3, borderpad=0, prop=fonts["body"])

        ax.set_title(title, fontproperties=fonts["body_semi"],
                     fontsize=9, pad=8)

    search_colors = ["#2563EB", "#06B6D4", "#10B981", "#F59E0B", "#EF4444",
                     "#8B5CF6", "#EC4899"]
    draw_donut(ax_donut_search, latest_data["search_detail"],
               "Search Engines ({})".format(get_week_label(latest)),
               search_colors)

    social_colors = ["#E60023", "#1877F2", "#E4405F", "#0A66C2",
                     "#1DA1F2", "#FF4500", "#FF0000", "#000000"]
    draw_donut(ax_donut_social, latest_data["social_detail"],
               "Social Media ({})".format(get_week_label(latest)),
               social_colors)

    # --- Lightweight connector lines from donuts to bar segments ---
    from matplotlib.patches import ConnectionPatch

    latest_idx = n - 1

    # Search Engine: top of the positive bar stack
    search_top = pos_direct[latest_idx] + pos_social[latest_idx] + pos_search[latest_idx]
    # Social Media: just above direct, in the social slice
    social_top = pos_direct[latest_idx] + pos_social[latest_idx]

    # Point to the right edge of the latest bar
    bar_right_x = latest_idx + bar_width / 2 + 0.15

    # Connector from search donut to top of latest bar
    con_search = ConnectionPatch(
        xyA=(-0.05, 0.5), coordsA=ax_donut_search.transAxes,
        xyB=(bar_right_x, search_top * 0.92), coordsB=ax_bar.transData,
        arrowstyle="->", shrinkA=2, shrinkB=3,
        color="#C9CDD3", linewidth=0.7, linestyle=(0, (4, 3)),
        mutation_scale=7,
    )
    fig.add_artist(con_search)
    con_search.set_zorder(0)

    # Connector from social donut to social slice of latest bar
    con_social = ConnectionPatch(
        xyA=(-0.05, 0.5), coordsA=ax_donut_social.transAxes,
        xyB=(bar_right_x, social_top * 0.95), coordsB=ax_bar.transData,
        arrowstyle="->", shrinkA=2, shrinkB=3,
        color="#C9CDD3", linewidth=0.7, linestyle=(0, (4, 3)),
        mutation_scale=7,
    )
    fig.add_artist(con_social)
    con_social.set_zorder(0)

    # --- Title --- use dash instead of em-dash (Michroma may lack the glyph)
    fig.suptitle("Catherine Truman Architects  -  Weekly Site Traffic",
                 fontproperties=fonts["title"], fontsize=13, y=0.96)

    # Logo is rendered in the email HTML, not in the chart image

    # Save
    fig.savefig(output_path, dpi=150, bbox_inches="tight",
                facecolor="white", edgecolor="none", pad_inches=0.3)
    plt.close(fig)
    print("Chart saved: {}".format(output_path))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CTAI Weekly Visual Report")
    parser.add_argument("--log-dir", type=str, default=None)
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--weeks", type=int, default=8)
    args = parser.parse_args()

    log_dir = args.log_dir or LOG_DIR

    print("Parsing logs from: {}".format(log_dir))
    entries = parse_all_logs(log_dir)
    print("Total entries: {:,}".format(len(entries)))

    print("Classifying IPs...")
    profiles = classify_all(entries)

    print("Building weekly data (unique visitors)...")
    weekly_data = build_weekly_data(entries, profiles)
    weeks = get_recent_weeks(weekly_data, args.weeks)
    print("Weeks: {} to {}".format(weeks[0], weeks[-1]))

    fonts = setup_fonts()

    if args.output:
        output_path = args.output
    else:
        output_path = os.path.join(os.path.dirname(__file__),
                                   "chart_weekly_{}.png".format(weeks[-1]))

    render_chart(weekly_data, weeks, output_path, fonts)

    latest = weeks[-1]
    d = weekly_data[latest]
    pos_total = d["search"] + d["social"] + d["direct_other"]
    neg_total = (d["risk_scanner"] + d["benign_scanner"] + d["wp_recon"]
                 + d["designer"] + d["content"] + d["hosting"] + d["crawlers"]
                 + d.get("ref_spam", 0))
    print("\nLatest week ({}) summary:".format(latest))
    print("  Human unique visitors: {:,}".format(pos_total))
    print("    Search: {:,}, Social: {:,}, Direct & Other: {:,}".format(
        d["search"], d["social"], d["direct_other"]))
    print("  Mechanical unique visitors: {:,}".format(neg_total))

    return 0


if __name__ == "__main__":
    sys.exit(main())
