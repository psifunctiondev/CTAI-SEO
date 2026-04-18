#!/usr/bin/env python3
"""
Referrer spam detection for CTAI access logs.

These are fake referrer headers injected by bots hoping the site owner
will visit their domain out of curiosity. They are NOT real visitors.
"""

from typing import Optional
import re

# Known spam referrer domains (manually curated from log analysis)
SPAM_DOMAINS = {
    # Ukrainian funeral/ritual sites
    "vavilon-ritual.com.ua",
    "velesritual.com.ua",
    "ua.velesritual.com.ua",
    "ritual.net.ua",
    "www.prjadko.kiev.ua",
    "foto-na-pamjatnyk.com.ua",
    "pamjatnik.com.ua",
    "petritual.kiev.ua",
    "perevozki24.com.ua",

    # Russian spam
    "goods-mebel.ru",
    "visapedia.ru",
    "crimeatravels.ru",
    "antonpolenov.ru",
    "love18.ru",
    "arenda-avto-anapa.ru",
    "cosmo-tech.ru",
    "slotloom.ru",
    "neuropsy-centr.ru",
    "sochi.vet",
    "topkinopro.com",
    "potolki-enigma.ru",
    "redflix.ru",
    "dentastar.ru",
    "dubravushka.ru",

    # Belarusian spam
    "strong.by",
    "vodila.by",
    "mirstroy.by",
    "autostrong-m.by",
    "belsklad.by",
    "g5.by",
    "bywwo.shop",
    "av-avto.net",

    # Other spam
    "russische-fahrlehrer.de",
    "thephilosopher.net",
    "myrockshows.com",
    "isg-consult.com",
    "rochybylawoffice.com",
    "orbispro.it",
    "t4k.info",
    "nskokna.ru",
    "corsproxy.io",
    "www.dreamscent.az",
    "www.doubao.com",
    "www.adamsbeasley.com",
    "xn----7sbaubaqf2bce4adfs7hzb2e.xn--p1ai",
}

# Legitimate external referrers (architecture/design industry)
LEGIT_EXTERNAL = {
    "www.bostondesignguide.com",
    "nehomemag.com",
    "www.bostonmagazine.com",
    "bsa.app.neoncrm.com",
    "brookesandhill.com",
    "www.c2mgbuilders.com",
    "roslynna.com",
    "jsitestatus.com",
}


def is_referrer_spam(referrer):
    # type: (str) -> bool
    """Check if a referrer URL is known spam."""
    if not referrer or referrer == "-":
        return False
    ref_lower = referrer.lower()
    m = re.match(r'https?://([^/]+)', ref_lower)
    if not m:
        return False
    domain = m.group(1)

    # Direct match
    if domain in SPAM_DOMAINS:
        return True

    # Strip www. and check again
    bare = domain.lstrip("www.")
    if bare in SPAM_DOMAINS:
        return True

    return False


def get_referrer_domain(referrer):
    # type: (str) -> Optional[str]
    """Extract domain from referrer URL."""
    if not referrer or referrer == "-":
        return None
    m = re.match(r'https?://([^/]+)', referrer.lower())
    return m.group(1) if m else None
