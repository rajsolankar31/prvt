from src.link_scanner import (
    analyze_url_parameters, strip_tracking_params, scan_html_source,
    analyze_cookies, is_safe_public_url, scan_live_web_link,
)

HTML = """
<html><head>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>
<script src="https://static.hotjar.com/c/hotjar-1.js"></script>
<script>fbq('init','123'); document.addEventListener('keydown', function(e){}); navigator.sendBeacon('/x');</script>
</head><body>
<img src="https://px.ads.linkedin.com/collect?pid=1" width="1" height="1">
<noscript><img src="https://www.facebook.com/tr?id=1&ev=PageView"></noscript>
<script src="https://cdn.segment.com/analytics.js/v1/abc/analytics.min.js"></script>
</body></html>
"""

def test_url_parameters_masked_and_cleaned():
    url = "https://shop.example.com/p?id=7&fbclid=IwAR2XYZ9876543210&utm_source=x&ttclid=abc123456"
    names = [t["Parameter"] for t in analyze_url_parameters(url)]
    assert {"fbclid", "utm_source", "ttclid"} <= set(names)
    assert "*" in next(t for t in analyze_url_parameters(url) if t["Parameter"] == "fbclid")["Values"]
    assert strip_tracking_params(url) == "https://shop.example.com/p?id=7"

def test_html_tracker_detection_and_effects():
    r = scan_html_source(HTML, "https://news.example.org/a")
    names = {t["Tracker Name"] for t in r["third_party_trackers"]}
    assert {"Google Analytics", "Hotjar", "Meta (Facebook) Pixel", "LinkedIn Insight Tag", "Segment"} <= names
    for t in r["third_party_trackers"]:
        assert t["Effect on You"] and t["Data Collected"] and t["How To Reduce"]
    assert r["tracking_pixels"], "1x1 third-party pixel should be flagged"
    threats = {s["Threat Type"] for s in r["suspicious_scripts"]}
    assert "Keylogger / Keystroke Interceptor" in threats and "Beacon Data Exfiltration" in threats
    assert r["effects"] and r["category_counts"].get("Session Replay") == 1
    assert r["risk_level"] in ("Medium-High", "Critical")

def test_clean_page_is_low_risk():
    r = scan_html_source("<html><body><h1>Hi</h1><script src='/app.js'></script></body></html>", "https://a.example.com")
    assert r["third_party_trackers"] == [] and r["risk_level"] == "Low" and r["risk_score"] == 0

def test_cookie_analysis():
    c = analyze_cookies(["_ga=GA1.2.3; Path=/", "session=abc; Secure; HttpOnly; SameSite=Lax"], "a.example.com")
    assert len(c) == 1 and c[0]["Cookie"] == "_ga" and "no Secure" in c[0]["Weak Flags"]

def test_private_addresses_blocked():
    assert not is_safe_public_url("http://127.0.0.1:8000")
    assert not is_safe_public_url("http://localhost/admin")
    assert not is_safe_public_url("ftp://example.com")
    res = scan_live_web_link("http://169.254.169.254/latest/meta-data")
    assert res["is_accessible"] is False and any("Blocked" in m for m in res["threat_summary"])
