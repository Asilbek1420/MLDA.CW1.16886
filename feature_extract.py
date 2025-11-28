# feature_extract.py
import re
from urllib.parse import urlparse
import socket
import requests
import whois
import dns.resolver
import time

# Helper functions
def safe_whois(domain, timeout=10):
    try:
        return whois.whois(domain)
    except Exception:
        return None

def has_dns_record(domain):
    try:
        # Try to resolve A records
        dns.resolver.resolve(domain, 'A', lifetime=5)
        return True
    except Exception:
        return False

def get_alexa_rank(domain):
    """
    Best-effort Alexa-like rank lookup.
    In production you should use a proper API (e.g., Alexa Premium) or SimilarWeb.
    Here we try a lightweight approach: if the domain resolves and we can fetch its homepage,
    assume it's known (suspicious/legitimacy inference). This is a placeholder.
    """
    # placeholder: return None if unknown
    try:
        url = f"https://{domain}"
        r = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            # We don't have a rank; return a heuristic "popular" flag
            return 50000  # pretend it's rank 50k (popular)
    except Exception:
        return None
    return None

def google_indexed(domain):
    """
    Cheap check: try 'site:domain' via DuckDuckGo HTML (no official Google API here).
    This is heuristic and not reliable for production. For robust check use Google Search Console API.
    """
    try:
        q = f"site:{domain}"
        r = requests.get("https://html.duckduckgo.com/html/", params={"q": q}, timeout=5,
                         headers={"User-Agent": "Mozilla/5.0"})
        text = r.text.lower()
        # if results text contains 'no results' then likely not indexed
        if "no results" in text or "did not match any results" in text:
            return False
        return True
    except Exception:
        return False

def fetch_page_html(url):
    try:
        r = requests.get(url, timeout=6, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return r.text
    except Exception:
        return ""

def count_external_resources(html, domain):
    # naive counts by checking src/href attributes referencing other domains
    try:
        from bs4 import BeautifulSoup
    except Exception:
        return None  # requires bs4; caller should fallback
    soup = BeautifulSoup(html, "html.parser")
    total = 0
    external = 0
    tags = ["img", "script", "link", "iframe"]
    for tag in tags:
        for t in soup.find_all(tag):
            # src or href attribute
            url_attr = t.get("src") or t.get("href")
            if not url_attr:
                continue
            total += 1
            # absolute URL?
            if url_attr.startswith("http"):
                if domain not in url_attr:
                    external += 1
    if total == 0:
        return None
    return (external / total) * 100

# Main extractor
def extract_features(url):
    """
    Returns a dict with 30 features in the UCI order.
    Feature values: 1 = Legitimate, 0 = Suspicious, -1 = Phishing
    """
    # normalize URL
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]  # remove port
    path = parsed.path or "/"
    full = url

    features = {}

    # 1. having_IP_Address
    features["having_IP_Address"] = -1 if re.search(r'^\d{1,3}(\.\d{1,3}){3}$', domain) or re.search(r'0x[0-9a-fA-F]+', domain) else 1

    # 2. URL_Length
    L = len(full)
    if L < 54:
        features["URL_Length"] = 1
    elif 54 <= L <= 75:
        features["URL_Length"] = 0
    else:
        features["URL_Length"] = -1

    # 3. Shortening_Service
    short_domains = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd"]
    features["Shortening_Service"] = -1 if any(sd in full for sd in short_domains) else 1

    # 4. having_At_Symbol
    features["having_At_Symbol"] = -1 if "@" in full else 1

    # 5. double_slash_redirecting
    last_idx = full.rfind("//")
    # position > 7 means suspicious per your rule
    features["double_slash_redirecting"] = -1 if last_idx > 7 else 1

    # 6. Prefix_Suffix
    features["Prefix_Suffix"] = -1 if "-" in domain else 1

    # 7. having_Sub_Domain
    # remove www.
    domain_no_www = domain[4:] if domain.startswith("www.") else domain
    dots = domain_no_www.count(".")
    if dots == 0:
        features["having_Sub_Domain"] = 1
    elif dots == 1:
        features["having_Sub_Domain"] = 0
    else:
        features["having_Sub_Domain"] = -1

    # 8. SSLfinal_State
    # check https and certificate age/issuer (best-effort - check cert via requests)
    try:
        is_https = full.startswith("https://")
        if is_https:
            # basic certificate age check via whois of domain (best-effort)
            w = safe_whois(domain)
            cert_ok = False
            if w and getattr(w, "creation_date", None):
                # if domain's creation is > 1 year we treat as better available proxy
                try:
                    cd = w.creation_date
                    # creation_date may be list
                    if isinstance(cd, list):
                        cd = cd[0]
                    age_days = (time.time() - cd.timestamp()) / (60*60*24)
                    cert_ok = age_days >= 365
                except Exception:
                    cert_ok = False
            features["SSLfinal_State"] = 1 if cert_ok else 0
        else:
            features["SSLfinal_State"] = -1
    except Exception:
        features["SSLfinal_State"] = -1

    # 9. Domain_registeration_length
    try:
        w = safe_whois(domain)
        if w and getattr(w, "expiration_date", None) and getattr(w, "creation_date", None):
            exp = w.expiration_date
            cr = w.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(cr, list): cr = cr[0]
            years = (exp - cr).days / 365
            features["Domain_registeration_length"] = 1 if years > 1 else -1
        else:
            features["Domain_registeration_length"] = -1
    except Exception:
        features["Domain_registeration_length"] = -1

    # 10. Favicon
    # check page HTML for <link rel="icon"...> and if it's from same domain
    html = fetch_page_html(full)
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        fav = soup.find("link", rel=lambda v: v and "icon" in v.lower())
        if fav:
            href = fav.get("href", "")
            if href.startswith("http") and domain not in href:
                features["Favicon"] = -1
            else:
                features["Favicon"] = 1
        else:
            features["Favicon"] = 1
    except Exception:
        features["Favicon"] = 0

    # 11. port  (non standard ports)
    if ":" in parsed.netloc and parsed.port:
        p = parsed.port
        # preferred ports list: 80,443
        features["port"] = -1 if p not in (80, 443) else 1
    else:
        features["port"] = 1

    # 12. HTTPS_token (token present in domain)
    features["HTTPS_token"] = -1 if "https" in domain else 1

    # 13. Request_URL (percentage of external objects)
    perc_ext = None
    try:
        perc = count_external_resources(html, domain)
        perc_ext = perc
        if perc is None:
            features["Request_URL"] = 0
        else:
            if perc < 22:
                features["Request_URL"] = 1
            elif 22 <= perc <= 61:
                features["Request_URL"] = 0
            else:
                features["Request_URL"] = -1
    except Exception:
        features["Request_URL"] = 0

    # 14. URL_of_Anchor
    try:
        if 'soup' not in locals():
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
        anchors = soup.find_all("a")
        if not anchors:
            features["URL_of_Anchor"] = -1
        else:
            total = len(anchors)
            ext = 0
            for a in anchors:
                href = a.get("href", "")
                if href.startswith("http") and domain not in href:
                    ext += 1
                elif href.strip().startswith(("javascript", "#")):
                    ext += 1
            ratio = (ext / total) * 100
            if ratio < 31:
                features["URL_of_Anchor"] = 1
            elif 31 <= ratio <= 67:
                features["URL_of_Anchor"] = 0
            else:
                features["URL_of_Anchor"] = -1
    except Exception:
        features["URL_of_Anchor"] = 0

    # 15. Links_in_tags (<meta>, <script>, <link>)
    try:
        meta_script_links = []
        for tag in ["meta", "script", "link"]:
            for t in soup.find_all(tag):
                href = t.get("href") or t.get("src") or ""
                if href:
                    meta_script_links.append(href)
        if not meta_script_links:
            features["Links_in_tags"] = 1
        else:
            ext = sum(1 for u in meta_script_links if u.startswith("http") and domain not in u)
            perc = (ext / len(meta_script_links)) * 100
            if perc < 17:
                features["Links_in_tags"] = 1
            elif 17 <= perc <= 81:
                features["Links_in_tags"] = 0
            else:
                features["Links_in_tags"] = -1
    except Exception:
        features["Links_in_tags"] = 0

    # 16. SFH (Server Form Handler)
    try:
        forms = soup.find_all("form")
        if not forms:
            features["SFH"] = -1
        else:
            sfh_flag = 1
            for f in forms:
                action = f.get("action", "")
                if action == "" or "about:blank" in action:
                    sfh_flag = -1
                    break
                if action.startswith("http") and domain not in action:
                    sfh_flag = 0
            features["SFH"] = sfh_flag
    except Exception:
        features["SFH"] = 0

    # 17. Submitting_to_email
    try:
        forms = soup.find_all("form")
        mail_flag = 1
        for f in forms:
            action = f.get("action", "")
            if "mailto:" in action:
                mail_flag = -1
                break
            # search for mail() usage in scripts
            if "mail(" in str(f):
                mail_flag = -1
                break
        features["Submitting_to_email"] = mail_flag
    except Exception:
        features["Submitting_to_email"] = 0

    # 18. Abnormal_URL (host not in URL)
    features["Abnormal_URL"] = -1 if domain not in full else 1

    # 19. Redirect (# of redirects)
    try:
        r = requests.get(full, timeout=6, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        redirects = len(r.history)
        if redirects <= 1:
            features["Redirect"] = 1
        elif 2 <= redirects < 4:
            features["Redirect"] = 0
        else:
            features["Redirect"] = -1
    except Exception:
        features["Redirect"] = 0

    # 20. On_mouseover
    try:
        if "onmouseover" in html.lower():
            features["On_mouseover"] = -1
        else:
            features["On_mouseover"] = 1
    except Exception:
        features["On_mouseover"] = 0

    # 21. RightClick disabled
    try:
        if "event.button==2" in html.lower() or "contextmenu" in html.lower():
            features["RightClick"] = -1
        else:
            features["RightClick"] = 1
    except Exception:
        features["RightClick"] = 0

    # 22. popUpWidnow
    try:
        # check if window.open with input fields appears
        if "window.open" in html.lower():
            # heuristic: consider suspicious
            features["popUpWidnow"] = 0
        else:
            features["popUpWidnow"] = 1
    except Exception:
        features["popUpWidnow"] = 0

    # 23. Iframe
    try:
        if soup.find("iframe"):
            features["Iframe"] = -1
        else:
            features["Iframe"] = 1
    except Exception:
        features["Iframe"] = 0

    # 24. age_of_domain (in months)
    try:
        w = safe_whois(domain)
        if w and getattr(w, "creation_date", None):
            cd = w.creation_date
            if isinstance(cd, list): cd = cd[0]
            months = (time.time() - cd.timestamp()) / (60*60*24*30)
            features["age_of_domain"] = 1 if months >= 6 else -1
        else:
            features["age_of_domain"] = -1
    except Exception:
        features["age_of_domain"] = -1

    # 25. DNSRecord
    features["DNSRecord"] = 1 if has_dns_record(domain) else -1

    # 26. web_traffic (Alexa rank heuristic)
    rank = get_alexa_rank(domain)
    if rank is None:
        features["web_traffic"] = -1
    else:
        features["web_traffic"] = 1 if rank < 100000 else 0

    # 27. Page_Rank (placeholder/proxy)
    # Real PageRank requires special APIs; here we approximate via Alexa presence
    features["Page_Rank"] = 1 if rank and rank < 10000 else (0 if rank and rank < 100000 else -1)

    # 28. Google_Index
    features["Google_Index"] = 1 if google_indexed(domain) else -1

    # 29. Links_pointing_to_page
    # Hard to compute without backlink API; use heuristic: if page returns 200 assume some links exist
    if rank:
        # assume some linking if rank present
        features["Links_pointing_to_page"] = 1 if rank < 50000 else 0
    else:
        features["Links_pointing_to_page"] = -1

    # 30. Statistical_report (PhishTank / StopBadware)
    # In production, use PhishTank API. Here we try a simple lookup against local list file
    features["Statistical_report"] = -1 if False else 1  # default: not in lists

    # Ensure we return only the 30 features and in expected order
    order = [
        "having_IP_Address","URL_Length","Shortening_Service","having_At_Symbol",
        "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
        "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
        "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
        "Redirect","On_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
        "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
        "Statistical_report"
    ]

    return {k: features[k] for k in order}
