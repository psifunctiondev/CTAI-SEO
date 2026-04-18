#!/usr/bin/env python3
"""
Send the CTAI visual report chart via email.

Usage:
    python send_visual_report.py                    # Send to Catherine's team + CC Quinn
    python send_visual_report.py --draft             # Draft: send only to Quinn
    python send_visual_report.py --test              # Dry run
    python send_visual_report.py --chart path.png    # Use specific chart file
"""

import os
import sys
import argparse
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SMTP_HOST = "mail.psifunction.com"
SMTP_PORT = 465
SMTP_USER = "doxa@psifunction.com"
REPORT_FROM = "Doxa — Psi Function <doxa@psifunction.com>"

# Production recipients
TO_PRODUCTION = ["ctruman@truman-architects.com", "mradloff@Truman-Architects.com"]
CC_PRODUCTION = ["quinn@psifunction.com"]

# Draft recipients (Quinn only)
TO_DRAFT = ["quinn@psifunction.com"]
CC_DRAFT = []

SECRETS_DIR = os.path.expanduser("~/.openclaw/workspace/.secrets")
SMTP_PASS_FILE = os.path.join(SECRETS_DIR, "email-psifunction.txt")


def get_smtp_password():
    # type: () -> str
    with open(SMTP_PASS_FILE, "r") as f:
        return f.read().strip()


# ---------------------------------------------------------------------------
# One-time synopsis for first production email
# ---------------------------------------------------------------------------

FIRST_RUN_SYNOPSIS = """
<div style="background-color: #f8f9fa; border-left: 4px solid #F0643A; padding: 16px 20px; margin: 20px 0; border-radius: 0 4px 4px 0;">
<p style="font-size: 15px; font-weight: 600; color: #1a2433; margin: 0 0 12px 0;">What am I looking at?</p>

<p style="font-size: 13px; color: #374151; margin: 0 0 10px 0; line-height: 1.6;">
This report separates your website traffic into <strong>human visitors</strong> (above the line) and <strong>automated/mechanical traffic</strong> (below the line). Here's what the mechanical categories mean:
</p>

<table style="font-size: 13px; color: #374151; border-collapse: collapse; width: 100%; margin-bottom: 12px;">
<tr style="border-bottom: 1px solid #e5e7eb;">
<td style="padding: 6px 12px 6px 0; font-weight: 600; white-space: nowrap; vertical-align: top;">Search Crawlers</td>
<td style="padding: 6px 0;">Google, Bing, and other search engines indexing your site. This is <em>good</em> &mdash; it means search engines are paying attention. No action needed.</td>
</tr>
<tr style="border-bottom: 1px solid #e5e7eb;">
<td style="padding: 6px 12px 6px 0; font-weight: 600; white-space: nowrap; vertical-align: top;">Security Risk</td>
<td style="padding: 6px 0;">Automated scanners probing for vulnerabilities &mdash; trying common file paths, looking for outdated plugins, or scanning for known exploits. Over the past 3 months, <strong>287 IPs</strong> generated <strong>184,000 of these requests</strong>, and the vast majority hit 404 (page not found) because the vulnerabilities they're looking for don't exist on your site. This is normal internet background noise &mdash; every website sees this.</td>
</tr>
<tr style="border-bottom: 1px solid #e5e7eb;">
<td style="padding: 6px 12px 6px 0; font-weight: 600; white-space: nowrap; vertical-align: top;">WP Recon</td>
<td style="padding: 6px 0;">Bots specifically probing your WordPress login page and trying to enumerate user accounts. <strong>59 IPs</strong> have attempted this. None have gained access &mdash; they all get redirected to the login screen without getting in.</td>
</tr>
<tr style="border-bottom: 1px solid #e5e7eb;">
<td style="padding: 6px 12px 6px 0; font-weight: 600; white-space: nowrap; vertical-align: top;">Referrer Spam</td>
<td style="padding: 6px 0;">Junk visits from spam domains (mostly overseas) trying to get their URLs into your analytics. No real visitors involved.</td>
</tr>
<tr>
<td style="padding: 6px 12px 6px 0; font-weight: 600; white-space: nowrap; vertical-align: top;">Benign Scanners</td>
<td style="padding: 6px 0;">Generic bots (SEO tools, uptime monitors, web archivers) that aren't harmful but aren't real visitors either.</td>
</tr>
</table>

<p style="font-size: 14px; font-weight: 600; color: #1a2433; margin: 12px 0 8px 0;">Do we need to do anything?</p>
<p style="font-size: 13px; color: #374151; margin: 0 0 8px 0; line-height: 1.6;">
<strong>The good news:</strong> None of these bots have successfully accessed your WordPress admin area. Your site is handling them correctly &mdash; they hit dead ends and move on.
</p>
<p style="font-size: 13px; color: #374151; margin: 0 0 8px 0; line-height: 1.6;">
<strong>Recommended hardening</strong> (we can coordinate with your web team):
</p>
<ul style="font-size: 13px; color: #374151; margin: 0 0 0 0; padding-left: 20px; line-height: 1.8;">
<li><strong>Limit login attempts</strong> &mdash; a plugin like Wordfence or Limit Login Attempts can auto-block IPs after failed logins</li>
<li><strong>Hide the wp-login page</strong> &mdash; moving the login URL stops most automated WordPress scanners cold</li>
<li><strong>Add a Web Application Firewall</strong> &mdash; services like Cloudflare (free tier available) can filter out scanner traffic before it reaches your server</li>
</ul>
<p style="font-size: 12px; color: #6c7d94; margin: 12px 0 0 0; font-style: italic;">
This explainer is included with the first report only. Future weekly reports will just contain the chart.
</p>
</div>
"""


def send_chart_email(chart_path, draft=False, dry_run=False, week_label=None,
                     first_run=False):
    # type: (str, bool, bool, str, bool) -> bool
    """Send the chart as an inline image email."""

    if not os.path.exists(chart_path):
        print("ERROR: Chart file not found: {}".format(chart_path))
        return False

    to_addrs = TO_DRAFT if draft else TO_PRODUCTION
    cc_addrs = CC_DRAFT if draft else CC_PRODUCTION
    all_recipients = to_addrs + cc_addrs

    if not week_label:
        week_label = "Week of {}".format(datetime.now().strftime("%B %d, %Y"))

    subject = "CTAI Website Traffic Report — {}".format(week_label)

    # Build email
    msg = MIMEMultipart("related")
    msg["From"] = REPORT_FROM
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    msg["Subject"] = subject

    # HTML body with inline chart + logo
    html = """\
<html>
<body style="font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; color: #1a2433; max-width: 900px;">
<p style="font-size: 14px; margin-bottom: 16px;">
Weekly website traffic summary for catherinetrumanarchitects.com.
</p>
<p style="font-size: 14px; margin-bottom: 8px;">
<strong>Above the line:</strong> organic human visitor traffic (search engine referrals, social media referrals, direct visits)<br>
<strong>Below the line:</strong> automated/mechanical traffic (scanners, bots, search engine crawlers)
</p>
<img src="cid:traffic_chart" style="max-width: 100%; height: auto;" />
{synopsis}
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top: 24px; border-top: 1px solid #e5e7eb; padding-top: 16px;">
<tr>
<td style="font-size: 11px; color: #9ca3af; vertical-align: middle;">Questions? Reply to this email.</td>
<td style="text-align: right; vertical-align: middle;">
<span style="font-size: 11px; color: #9ca3af; vertical-align: middle;">Prepared by&ensp;</span>
<img src="cid:psi_logo" style="height: 22px; vertical-align: middle;" />
</td>
</tr>
</table>
</body>
</html>
"""

    synopsis_html = FIRST_RUN_SYNOPSIS if first_run else ""
    html = html.format(synopsis=synopsis_html)
    html_part = MIMEText(html, "html", "utf-8")
    msg.attach(html_part)

    # Attach chart as inline image
    with open(chart_path, "rb") as f:
        img_data = f.read()

    img = MIMEImage(img_data, _subtype="png")
    img.add_header("Content-ID", "<traffic_chart>")
    img.add_header("Content-Disposition", "inline", filename="ctai-traffic-report.png")
    msg.attach(img)

    # Attach Psi Function logo
    logo_path = os.path.join(os.path.dirname(__file__), "..", "assets", "psi_logo.png")
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as f:
            logo_data = f.read()
        logo = MIMEImage(logo_data, _subtype="png")
        logo.add_header("Content-ID", "<psi_logo>")
        logo.add_header("Content-Disposition", "inline", filename="psi-function-logo.png")
        msg.attach(logo)

    if draft:
        subject_prefix = "[DRAFT] "
        msg.replace_header("Subject", subject_prefix + subject)

    if dry_run:
        print("\n[DRY RUN] Would send email:")
        print("  From: {}".format(REPORT_FROM))
        print("  To: {}".format(", ".join(to_addrs)))
        if cc_addrs:
            print("  CC: {}".format(", ".join(cc_addrs)))
        print("  Subject: {}".format(msg["Subject"]))
        print("  Chart: {} ({:.0f} KB)".format(chart_path, len(img_data) / 1024))
        return True

    password = get_smtp_password()

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, password)
            server.send_message(msg, to_addrs=all_recipients)
        print("Email sent to: {}".format(", ".join(all_recipients)))
        return True
    except Exception as e:
        print("ERROR sending email: {}".format(e))
        return False


def main():
    parser = argparse.ArgumentParser(description="Send CTAI visual report")
    parser.add_argument("--chart", type=str, default=None,
                        help="Path to chart PNG")
    parser.add_argument("--draft", action="store_true",
                        help="Send draft to Quinn only")
    parser.add_argument("--test", action="store_true",
                        help="Dry run")
    parser.add_argument("--week", type=str, default=None,
                        help="Week label for subject line")
    parser.add_argument("--first-run", action="store_true",
                        help="Include one-time explainer synopsis")
    args = parser.parse_args()

    # Find latest chart if not specified
    if args.chart:
        chart_path = args.chart
    else:
        analysis_dir = os.path.dirname(__file__)
        charts = sorted([f for f in os.listdir(analysis_dir)
                         if f.startswith("chart_weekly_") and f.endswith(".png")])
        if not charts:
            print("ERROR: No chart files found in {}".format(analysis_dir))
            sys.exit(1)
        chart_path = os.path.join(analysis_dir, charts[-1])

    print("Chart: {}".format(chart_path))
    mode = "DRAFT" if args.draft else "PRODUCTION"
    print("Mode: {}".format(mode))

    ok = send_chart_email(chart_path, draft=args.draft, dry_run=args.test,
                          week_label=args.week, first_run=args.first_run)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
