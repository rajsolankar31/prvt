import re
import ipaddress
import socket
import urllib.parse
from typing import Dict, Any, List, Optional
import requests
from bs4 import BeautifulSoup
from .document_scanner import mask_evidence

# ---------------------------------------------------------------------------
# TRACKER DATABASE
# vendor, category, severity, detection pattern, what it collects,
# the effect on the visitor, and how to reduce it.
# ---------------------------------------------------------------------------
def _t(vendor, category, severity, pattern, collects, effect, mitigation):
    return {
        "vendor": vendor, "category": category, "severity": severity,
        "rx": re.compile(pattern, re.I),
        "collects": collects, "effect": effect, "mitigation": mitigation,
    }

TRACKER_DB: Dict[str, Dict[str, Any]] = {
    "Google Analytics": _t(
        "Google", "Analytics", "Medium",
        r"google-analytics\.com|googletagmanager\.com/gtag|analytics\.js|gtag/js|\bga\(\s*['\"]create",
        "Pages viewed, time on page, device, approximate location, referrer, client ID",
        "Links your visits across sessions and sites that use the same Google cookie.",
        "Use a tracker blocker (uBlock Origin) or the Google Analytics Opt-out add-on."),
    "Google Tag Manager": _t(
        "Google", "Tag Manager", "Medium",
        r"googletagmanager\.com/gtm\.js|googletagmanager\.com/ns\.html|GTM-[A-Z0-9]{4,}",
        "Loads other tags dynamically; can add any tracker without code review",
        "Hidden container: more trackers can load than are visible in the page source.",
        "Block googletagmanager.com; if you own the site, audit the container's tags."),
    "Google Ads / DoubleClick": _t(
        "Google", "Advertising", "High",
        r"doubleclick\.net|googleadservices\.com|googlesyndication\.com|pagead2|adservice\.google",
        "Ad impressions, clicks, browsing interests, conversion events",
        "Builds an advertising profile and retargets you with ads across the web.",
        "Disable ad personalization; block ad domains."),
    "Meta (Facebook) Pixel": _t(
        "Meta", "Advertising", "High",
        r"connect\.facebook\.net|fbevents\.js|facebook\.com/tr\b|fbq\s*\(",
        "Page views, purchases, form events, hashed email/phone, browser ID (fbp)",
        "Shares your activity with Meta even if you are logged out or have no account.",
        "Use browser containers or block facebook.net and facebook.com/tr."),
    "TikTok Pixel": _t(
        "TikTok / ByteDance", "Advertising", "High",
        r"analytics\.tiktok\.com|ttq\.load|tiktok\.com/i18n/pixel",
        "Page views, clicks, conversions, device fingerprint, IP",
        "Sends behavior to TikTok for ad targeting and cross-site profiling.",
        "Block analytics.tiktok.com."),
    "LinkedIn Insight Tag": _t(
        "LinkedIn / Microsoft", "Advertising", "High",
        r"snap\.licdn\.com|px\.ads\.linkedin\.com|_linkedin_partner_id",
        "Visits, job title/company of logged-in users, conversions",
        "Ties your visit to your professional identity.",
        "Block snap.licdn.com and px.ads.linkedin.com."),
    "Twitter / X Pixel": _t(
        "X Corp", "Advertising", "High",
        r"static\.ads-twitter\.com|analytics\.twitter\.com|t\.co/i/adsct|twq\s*\(",
        "Page views, conversions, ad engagement",
        "Links your browsing to your X account for ad targeting.",
        "Block ads-twitter.com and analytics.twitter.com."),
    "Pinterest Tag": _t(
        "Pinterest", "Advertising", "Medium",
        r"s\.pinimg\.com/ct/core\.js|ct\.pinterest\.com|pintrk\s*\(",
        "Page views, add-to-cart, purchases",
        "Builds an interest profile for Pinterest ads.",
        "Block ct.pinterest.com."),
    "Snapchat Pixel": _t(
        "Snap", "Advertising", "Medium",
        r"sc-static\.net/scevent|tr\.snapchat\.com|snaptr\s*\(",
        "Page events, conversions, device info",
        "Shares events with Snap for ad attribution.",
        "Block sc-static.net and tr.snapchat.com."),
    "Microsoft Ads / Clarity": _t(
        "Microsoft", "Session Replay", "High",
        r"clarity\.ms|bat\.bing\.com|uetq\b",
        "Mouse movement, clicks, scrolling, page recordings, ad conversions",
        "Records how you interact with the page; may capture typed content if not masked.",
        "Block clarity.ms and bat.bing.com."),
    "Criteo": _t(
        "Criteo", "Advertising", "High",
        r"criteo\.com|criteo\.net|static\.criteo",
        "Products viewed, cart contents, hashed email",
        "Retargets you with the exact products you viewed, across other sites.",
        "Block criteo.com and criteo.net."),
    "Taboola / Outbrain": _t(
        "Taboola / Outbrain", "Advertising", "Medium",
        r"taboola\.com|outbrain\.com|outbrainimg\.com",
        "Articles read, interests, clicks",
        "Content-recommendation profiling across publishers.",
        "Block taboola.com and outbrain.com."),
    "Hotjar": _t(
        "Hotjar", "Session Replay", "High",
        r"static\.hotjar\.com|hotjar\.js|hj\s*\(\s*['\"]identify|_hjSettings",
        "Screen recordings, heatmaps, clicks, scroll depth, form interactions",
        "Your session can be replayed by the site owner, possibly including form input.",
        "Block hotjar.com; avoid typing sensitive data on the page."),
    "FullStory": _t(
        "FullStory", "Session Replay", "High",
        r"fullstory\.com|edge\.fullstory|/fs\.js",
        "Pixel-perfect session replay, keystrokes, clicks, rage-click detection",
        "Your entire browsing session can be recorded and replayed.",
        "Block fullstory.com."),
    "LogRocket": _t(
        "LogRocket", "Session Replay", "High",
        r"logrocket\.com|cdn\.lr-ingest|LogRocket\.init",
        "Session video, network requests, console logs, user identity",
        "Recorded sessions may contain personal data.",
        "Block logrocket.com and lr-ingest.io."),
    "Mouseflow / Lucky Orange / Smartlook": _t(
        "Various", "Session Replay", "High",
        r"mouseflow\.com|luckyorange\.(?:com|net)|smartlook\.com|inspectlet\.com",
        "Session recordings, heatmaps, form analytics",
        "Replays your interactions and may capture form fields.",
        "Block the vendor domains."),
    "CrazyEgg": _t(
        "CrazyEgg", "Heatmap", "Medium",
        r"script\.crazyegg\.com|crazyegg\.com",
        "Click and scroll heatmaps",
        "Tracks where you click and scroll.",
        "Block crazyegg.com."),
    "Mixpanel / Amplitude / Heap": _t(
        "Product analytics", "Analytics", "Medium",
        r"mixpanel\.com|cdn\.amplitude\.com|api\.amplitude\.com|heap-analytics|heapanalytics\.com",
        "Event-level behavior tied to a persistent user ID",
        "Detailed per-user behavior timeline.",
        "Block the vendor domains."),
    "Segment": _t(
        "Twilio Segment", "Customer Data Platform", "High",
        r"cdn\.segment\.com|api\.segment\.io|analytics\.load\(",
        "Forwards your events and identity to many downstream vendors",
        "One script can fan your data out to dozens of third parties.",
        "Block segment.com and segment.io."),
    "HubSpot": _t(
        "HubSpot", "Marketing Automation", "Medium",
        r"js\.hs-scripts\.com|js\.hsforms\.net|hs-analytics\.net|hubspot\.com/analytics|_hsq",
        "Visits tied to an email/contact record, form submissions",
        "Connects anonymous visits to your identity once you submit a form or click an email link.",
        "Block hs-scripts.com and hs-analytics.net."),
    "Adobe Analytics": _t(
        "Adobe", "Analytics", "Medium",
        r"omtrdc\.net|2o7\.net|adobedtm\.com|demdex\.net|s_code\.js|AppMeasurement",
        "Page views, visitor ID, audience segments",
        "Shares a cross-site visitor ID through Adobe Experience Cloud.",
        "Block omtrdc.net and demdex.net."),
    "Yandex Metrica": _t(
        "Yandex", "Analytics", "High",
        r"mc\.yandex\.(?:ru|com)|metrika|ym\s*\(\s*\d+",
        "Visits, clicks, Webvisor session recording",
        "Data and recordings go to Yandex servers.",
        "Block mc.yandex.ru."),
    "Matomo / Plausible / Fathom": _t(
        "Privacy-focused analytics", "Analytics", "Low",
        r"matomo\.(?:js|php)|piwik\.(?:js|php)|plausible\.io/js|usefathom\.com",
        "Aggregated page views (often cookieless)",
        "Lower privacy impact; usually first-party or cookieless.",
        "Usually acceptable."),
    "FingerprintJS": _t(
        "Fingerprint", "Fingerprinting", "High",
        r"fingerprintjs|fpjs\.io|fingerprint\.com|openfpcdn\.io|getHighEntropyValues",
        "Browser/device fingerprint (canvas, fonts, GPU, audio)",
        "Identifies your device even with cookies cleared or in private mode.",
        "Use Brave/Firefox fingerprint protection; block fpjs.io."),
    "Social Media Widgets": _t(
        "Meta / X / LinkedIn", "Social Widget", "Medium",
        r"facebook\.com/plugins|platform\.twitter\.com/widgets|platform\.linkedin\.com",
        "Your visit, even if you never click the button",
        "Like/Share widgets report that you visited the page.",
        "Block social widgets or use a social-button blocker."),
    "Cloudflare Web Analytics": _t(
        "Cloudflare", "Analytics", "Low",
        r"static\.cloudflareinsights\.com|cloudflareinsights\.com/beacon",
        "Aggregated, cookieless page metrics",
        "Low impact; no cross-site profiling.",
        "Usually acceptable."),
}

SEVERITY_WEIGHT = {"High": 10, "Medium": 6, "Low": 2}

# Common tracking cookie names
TRACKING_COOKIES = {
    "_ga": "Google Analytics client ID",
    "_gid": "Google Analytics session ID",
    "_gat": "Google Analytics rate limiter",
    "_gcl_au": "Google Ads conversion linker",
    "_fbp": "Meta Pixel browser ID",
    "_fbc": "Meta click ID",
    "_ttp": "TikTok Pixel ID",
    "_hjid": "Hotjar user ID",
    "_hjSessionUser": "Hotjar user ID",
    "hubspotutk": "HubSpot visitor identity",
    "__hstc": "HubSpot tracking cookie",
    "_uetsid": "Microsoft Ads session ID",
    "_uetvid": "Microsoft Ads visitor ID",
    "ajs_anonymous_id": "Segment anonymous user ID",
    "IDE": "DoubleClick advertising ID",
    "_clck": "Microsoft Clarity user ID",
    "_pin_unauth": "Pinterest tracking ID",
    "li_fat_id": "LinkedIn click ID",
}

# Suspicious / malicious script behaviours
SUSPICIOUS_SCRIPT_PATTERNS = {
    "Keylogger / Keystroke Interceptor": re.compile(r"(?i)(?:addEventListener\s*\(\s*['\"](?:keyup|keydown|keypress)['\"]|\.onkeypress\s*=)"),
    "Hidden Form Password Harvesting": re.compile(r"(?i)(?:input\[type=['\"]password['\"]\]|document\.forms.*\.password)"),
    "Clipboard Access / Hijacking": re.compile(r"(?i)(?:navigator\.clipboard\.readText|document\.execCommand\s*\(\s*['\"]copy['\"]\)|\.clipboardData)"),
    "Cryptominer WebAssembly Worker": re.compile(r"(?i)(?:coinhive|cryptonight|webminer|Wasm\.instantiate.*(?:miner|crypto))"),
    "Obfuscated Payload Execution": re.compile(r"(?i)(?:eval\s*\(|unescape\s*\(|String\.fromCharCode\s*\(|window\[['\"]eval['\"]\])"),
    "Browser Fingerprinting Canvas Probe": re.compile(r"(?i)(?:toDataURL\s*\(\s*['\"]image\/png['\"]\)|\.getImageData\s*\(.*canvas)"),
    "AudioContext Fingerprinting": re.compile(r"(?i)(?:OfflineAudioContext|createOscillator|createDynamicsCompressor)"),
    "Geolocation Request": re.compile(r"(?i)navigator\.geolocation\.(?:getCurrentPosition|watchPosition)"),
    "Beacon Data Exfiltration": re.compile(r"(?i)navigator\.sendBeacon\s*\("),
}
MEDIUM_THREATS = {"Geolocation Request", "Beacon Data Exfiltration", "Obfuscated Payload Execution"}

SCRIPT_DANGER = {
    "Keylogger": "Monitors user keystrokes",
    "Clipboard": "Reads user clipboard contents",
    "Fingerprint": "Generates a unique hardware fingerprint",
    "Obfuscated": "Executes dynamic, uninspected payloads",
    "Geolocation": "Requests your precise location",
    "Beacon": "Silently sends data to a server, often when you leave the page",
    "Password": "Can capture typed passwords",
}

# URL tracking query parameters
TRACKING_QUERY_PARAMS = {
    "fbclid": "Meta / Facebook click identifier (cross-site user tracking)",
    "gclid": "Google Ads click identifier (ad attribution tracking)",
    "gbraid": "Google Ads iOS click identifier",
    "wbraid": "Google Ads web-to-app click identifier",
    "dclid": "Google DoubleClick click identifier",
    "msclkid": "Microsoft Bing click identifier",
    "ttclid": "TikTok click identifier",
    "twclid": "X / Twitter click identifier",
    "li_fat_id": "LinkedIn click identifier",
    "igshid": "Instagram share identifier",
    "yclid": "Yandex click identifier",
    "mc_eid": "Mailchimp individual subscriber email ID",
    "mc_cid": "Mailchimp campaign ID",
    "utm_source": "Campaign traffic source tag",
    "utm_medium": "Campaign medium tag",
    "utm_campaign": "Campaign name tag",
    "utm_term": "Paid search keyword tracking",
    "utm_content": "Ad variant attribution tracking",
    "utm_id": "Campaign ID tag",
    "_hsenc": "HubSpot encrypted contact identifier",
    "_hsmi": "HubSpot marketing message ID",
    "vero_id": "Vero subscriber identifier",
    "_ga": "Google Analytics cross-domain client ID",
    "_gl": "Google cross-domain linker",
}


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def _host(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _registrable(host: str) -> str:
    """Approximate registrable domain (last two labels; three for co.uk style)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_safe_public_url(url: str) -> bool:
    """Blocks localhost / private-network targets so the scanner can't be used to probe internal hosts."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        for info in socket.getaddrinfo(parsed.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        return True
    except Exception:
        return False


def analyze_url_parameters(url: str) -> List[Dict[str, Any]]:
    """Inspects query parameters in a URL for user tracking and cross-site identifiers."""
    findings = []
    try:
        params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        for key, values in params.items():
            if key.lower() in TRACKING_QUERY_PARAMS:
                findings.append({
                    "Parameter": key,
                    "Values": ", ".join(mask_evidence(v, keep_chars=3) for v in values),
                    "Category": "URL Tracking Parameter",
                    "Description": TRACKING_QUERY_PARAMS[key.lower()],
                    "Privacy Impact": "Links this link visit to your specific user profile/click ID across the web.",
                })
    except Exception:
        pass
    return findings


def strip_tracking_params(url: str) -> str:
    """Returns the URL with known tracking parameters removed (a clean, shareable link)."""
    try:
        p = urllib.parse.urlparse(url)
        kept = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
                if k.lower() not in TRACKING_QUERY_PARAMS]
        return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(kept)))
    except Exception:
        return url


def analyze_cookies(set_cookie_headers: List[str], page_host: str) -> List[Dict[str, Any]]:
    """Flags known tracking cookies, third-party cookies and weak cookie flags."""
    out = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        known = next((d for k, d in TRACKING_COOKIES.items() if name == k or name.startswith(k)), None)
        flags = [f for f, ok in (("no Secure", "secure" in low), ("no HttpOnly", "httponly" in low),
                                 ("no SameSite", "samesite" in low)) if not ok]
        dom = re.search(r"domain=([^;]+)", low)
        third = bool(dom and _registrable(dom.group(1).strip().lstrip(".")) != _registrable(page_host))
        if known or third:
            out.append({
                "Cookie": name,
                "Purpose": known or "Third-party cookie",
                "Third-Party": "Yes" if third else "No",
                "Weak Flags": ", ".join(flags) or "None",
                "Effect on You": "Persistent identifier that follows you between visits." if known else "Set by another domain.",
            })
    return out


def _match_trackers(blob: str) -> List[str]:
    return [name for name, t in TRACKER_DB.items() if t["rx"].search(blob)]


# ---------------------------------------------------------------------------
# CORE ANALYSIS (works on raw HTML, so it also runs offline on pasted source)
# ---------------------------------------------------------------------------
def analyze_html(html: str, page_url: str = "", response_headers: Optional[Dict[str, str]] = None,
                 set_cookies: Optional[List[str]] = None) -> Dict[str, Any]:
    soup = BeautifulSoup(html or "", "html.parser")
    page_host = _host(page_url)
    page_reg = _registrable(page_host) if page_host else ""

    # Every external resource reference
    resources = []
    for tag, attr in (("script", "src"), ("img", "src"), ("iframe", "src"), ("link", "href"),
                      ("embed", "src"), ("source", "src")):
        for el in soup.find_all(tag):
            u = el.get(attr)
            if u:
                resources.append((tag, urllib.parse.urljoin(page_url, u) if page_url else u, el))

    inline_scripts = [s.string for s in soup.find_all("script") if s.string]
    inline_blob = "\n".join(inline_scripts)
    noscript_html = " ".join(str(n) for n in soup.find_all("noscript"))

    # Known trackers: resource URLs, inline code, <noscript> fallback pixels
    found: Dict[str, Dict[str, Any]] = {}
    def _add(name, evidence, via):
        f = found.setdefault(name, {"evidence": [], "via": set()})
        f["evidence"].append(evidence)
        f["via"].add(via)

    for tag, u, _el in resources:
        for name in _match_trackers(u):
            _add(name, u, tag)
    for name in _match_trackers(inline_blob):
        _add(name, "inline script", "inline script")
    for name in _match_trackers(noscript_html):
        _add(name, "<noscript> fallback pixel", "noscript pixel")

    trackers = []
    for name, f in found.items():
        t = TRACKER_DB[name]
        trackers.append({
            "Tracker Name": name, "Vendor": t["vendor"], "Category": t["category"],
            "Severity": t["severity"], "Loaded Via": ", ".join(sorted(f["via"])),
            "Evidence": f["evidence"][0][:90],
            "Data Collected": t["collects"], "Effect on You": t["effect"],
            "How To Reduce": t["mitigation"],
        })
    sev_order = {"High": 0, "Medium": 1, "Low": 2}
    trackers.sort(key=lambda r: sev_order[r["Severity"]])

    # Hidden pixels / iframes from other domains
    pixels = []
    for tag, u, el in resources:
        if tag not in ("img", "iframe"):
            continue
        w, h = str(el.get("width", "")).strip(), str(el.get("height", "")).strip()
        style = (el.get("style") or "").replace(" ", "").lower()
        tiny = w in ("0", "1") or h in ("0", "1") or "display:none" in style or "visibility:hidden" in style
        host = _host(u)
        if tiny and host and (not page_reg or _registrable(host) != page_reg):
            pixels.append({"Type": "Hidden pixel / iframe", "Domain": host, "URL": u[:90],
                           "Effect on You": "Fires a request to this domain on every page load, revealing your IP and visit."})

    # Third-party domains contacted
    counts: Dict[str, int] = {}
    for _tag, u, _el in resources:
        host = _host(u)
        if host and page_reg and _registrable(host) != page_reg:
            counts[host] = counts.get(host, 0) + 1
    domains = [{"Domain": d, "Resources": c} for d, c in sorted(counts.items(), key=lambda x: -x[1])]

    # Suspicious scripts
    suspicious = []
    for attack, rx in SUSPICIOUS_SCRIPT_PATTERNS.items():
        m = rx.search(inline_blob)
        if m:
            danger = next((v for k, v in SCRIPT_DANGER.items() if k in attack),
                          "Exfiltrates credentials or consumes CPU resources")
            suspicious.append({
                "Threat Type": attack,
                "Severity": "Medium" if attack in MEDIUM_THREATS else "High",
                "Detected Code Pattern": mask_evidence(m.group(0), keep_chars=4),
                "Security Danger": danger,
            })

    # Headers (only when a real response is available)
    security_headers, missing = {}, []
    if response_headers is not None:
        h = {k.lower(): v for k, v in response_headers.items()}
        security_headers = {
            "strict-transport-security": h.get("strict-transport-security", "Missing"),
            "content-security-policy": "Present" if "content-security-policy" in h else "Missing",
            "referrer-policy": h.get("referrer-policy", "Missing (default reveals referer)"),
            "permissions-policy": "Present" if "permissions-policy" in h else "Missing",
        }
        if "content-security-policy" not in h:
            missing.append("Content-Security-Policy (permits injection of external scripts)")
        if "strict-transport-security" not in h:
            missing.append("HSTS (permits insecure downgraded HTTP connections)")
        if "referrer-policy" not in h:
            missing.append("Referrer-Policy (browser leaks visiting URL to destination)")

    return {
        "third_party_trackers": trackers,
        "tracking_pixels": pixels,
        "third_party_domains": domains,
        "suspicious_scripts": suspicious,
        "cookies": analyze_cookies(set_cookies or [], page_host),
        "security_headers": security_headers,
        "missing_privacy_headers": missing,
    }


def _build_effects(r: Dict[str, Any]) -> Dict[str, Any]:
    """Plain-language summary of what the findings mean for the visitor."""
    cats: Dict[str, int] = {}
    for t in r["third_party_trackers"]:
        cats[t["Category"]] = cats.get(t["Category"], 0) + 1

    fx = []
    if cats.get("Session Replay") or cats.get("Heatmap"):
        fx.append("Your clicks, scrolling and possibly typed text can be recorded and replayed by the site owner.")
    if cats.get("Advertising"):
        fx.append("Your visit can be sent to ad networks to build an interest profile and retarget you on other sites.")
    if cats.get("Fingerprinting") or any("Fingerprint" in s["Threat Type"] for s in r["suspicious_scripts"]):
        fx.append("Your device can be identified even without cookies, in private mode, or after clearing data.")
    if cats.get("Analytics") or cats.get("Customer Data Platform") or cats.get("Marketing Automation"):
        fx.append("Your behavior is logged against a persistent ID and can be linked to your identity (e.g. via email clicks or forms).")
    if r["url_trackers"]:
        fx.append("The link itself carries click IDs that tie this visit to an ad click or an email recipient.")
    if r["tracking_pixels"]:
        fx.append("Invisible pixels tell other companies about your visit, exposing your IP address and browser details.")
    if r["cookies"]:
        fx.append("Tracking cookies will keep an identifier in your browser between visits.")
    if any(s["Severity"] == "High" for s in r["suspicious_scripts"]):
        fx.append("Scripts on the page can capture keystrokes, passwords or clipboard data. Avoid entering sensitive information.")
    return {"category_counts": cats, "effects": fx}


def _score(r: Dict[str, Any]) -> None:
    s = min(len(r["url_trackers"]) * 6, 15)
    s += min(sum(SEVERITY_WEIGHT[t["Severity"]] for t in r["third_party_trackers"]), 40)
    s += min(len(r["tracking_pixels"]) * 3, 9)
    s += min(sum(25 if x["Severity"] == "High" else 10 for x in r["suspicious_scripts"]), 40)
    s += min(len(r["cookies"]) * 2, 6)
    s += min(len(r["missing_privacy_headers"]) * 3, 9)
    r["risk_score"] = min(100.0, round(float(s), 1))
    r["risk_level"] = "Critical" if r["risk_score"] >= 65 else "Medium-High" if r["risk_score"] >= 35 else "Low"


def scan_html_source(html: str, page_url: str = "") -> Dict[str, Any]:
    """Offline scan of pasted HTML source. No network request is made."""
    report: Dict[str, Any] = {
        "url": page_url, "is_accessible": True, "status_code": None, "final_url": page_url,
        "url_trackers": analyze_url_parameters(page_url) if page_url else [],
        "threat_summary": [],
        "clean_url": strip_tracking_params(page_url) if page_url else "",
    }
    report.update(analyze_html(html, page_url))
    report.update(_build_effects(report))
    _score(report)
    return report


def scan_live_web_link(url: str, timeout_seconds: int = 8) -> Dict[str, Any]:
    """
    Fetches a URL and audits it for:
    1. URL tracking parameters (gclid, fbclid, utm_*, ttclid ...)
    2. 25+ known tracker vendors by category, with data collected, effect and mitigation
    3. Hidden tracking pixels, third-party domains and tracking cookies
    4. Suspicious scripts (keyloggers, clipboard, fingerprinting, miners, beacons)
    5. Security headers and a combined 0-100 risk score
    """
    results: Dict[str, Any] = {
        "url": url, "is_accessible": False, "status_code": None, "final_url": url,
        "url_trackers": analyze_url_parameters(url),
        "third_party_trackers": [], "tracking_pixels": [], "third_party_domains": [],
        "suspicious_scripts": [], "cookies": [], "security_headers": {},
        "missing_privacy_headers": [], "category_counts": {}, "effects": [],
        "clean_url": strip_tracking_params(url),
        "risk_score": 0.0, "risk_level": "Low", "threat_summary": [],
    }

    if not is_safe_public_url(url):
        results["threat_summary"].append("Blocked: URL is invalid, unreachable, or points to a local/private network address.")
        return results

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DataPrivacyGuardian/2.0 PrivacyAuditor"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout_seconds, allow_redirects=True, stream=True)
        html = resp.raw.read(3_000_000, decode_content=True).decode(resp.encoding or "utf-8", errors="replace")

        results.update({"is_accessible": True, "status_code": resp.status_code, "final_url": resp.url})

        o, f = _host(url), _host(resp.url)
        if o and f and o != f:
            results["threat_summary"].append(f"Domain redirected: {o} -> {f}")

        try:
            set_cookies = resp.raw.headers.getlist("Set-Cookie")
        except Exception:
            set_cookies = [resp.headers["set-cookie"]] if resp.headers.get("set-cookie") else []

        results.update(analyze_html(html, resp.url, dict(resp.headers), set_cookies))
        results["clean_url"] = strip_tracking_params(resp.url)
        # URL params on both the requested and final (post-redirect) URL
        seen = {x["Parameter"] for x in results["url_trackers"]}
        results["url_trackers"] += [x for x in analyze_url_parameters(resp.url) if x["Parameter"] not in seen]
    except requests.exceptions.RequestException as e:
        results["threat_summary"].append(f"Connection failed / timeout: {e}")

    results.update(_build_effects(results))
    _score(results)
    return results
