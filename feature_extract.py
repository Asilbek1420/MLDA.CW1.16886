import re
import whois
import requests
from urllib.parse import urlparse
import datetime

def extract_features(url):
    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    features = {}

    # 1. having_IP_Address
    features["having_IP_Address"] = -1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 1

    # 2. URL_Length
    features["URL_Length"] = 1 if len(url) < 54 else (-1 if len(url) > 75 else 0)

    # 3. Shortining_Service
    short_domains = ["bit.ly", "goo.gl", "tinyurl.com", "ow.ly"]
    features["Shortining_Service"] = -1 if any(s in url for s in short_domains) else 1

    # 4. having_At_Symbol
    features["having_At_Symbol"] = -1 if "@" in url else 1

    # 5. double_slash_redirecting
    features["double_slash_redirecting"] = -1 if url.count("//") > 1 else 1

    # 6. Prefix_Suffix (Dash in domain)
    features["Prefix_Suffix"] = -1 if "-" in domain else 1

    # 7. having_Sub_Domain
    features["having_Sub_Domain"] = -1 if domain.count(".") > 2 else (0 if domain.count(".") == 2 else 1)

    # 8. SSLfinal_State
    features["SSLfinal_State"] = 1 if url.startswith("https") else -1

    # 9. Domain_registeration_length
    try:
        whois_info = whois.whois(domain)
        if isinstance(whois_info.expiration_date, list):
            expiration_date = whois_info.expiration_date[0]
        else:
            expiration_date = whois_info.expiration_date

        if expiration_date:
            delta = (expiration_date - datetime.datetime.now()).days
            features["Domain_registeration_length"] = 1 if delta > 365 else -1
        else:
            features["Domain_registeration_length"] = -1
    except:
        features["Domain_registeration_length"] = -1

    # 10. Favicon (placeholder)
    features["Favicon"] = 1  # requires HTML parsing

    # 11. port
    features["port"] = -1 if ":" in domain else 1

    # 12. HTTPS_token
    features["HTTPS_token"] = -1 if "https" in domain else 1

    # 13. Request_URL (placeholder)
    features["Request_URL"] = 1

    # 14. URL_of_Anchor (placeholder)
    features["URL_of_Anchor"] = 1

    # 15. Links_in_tags (placeholder)
    features["Links_in_tags"] = 1

    # 16. SFH (Server Form Handler) (placeholder)
    features["SFH"] = 1

    # 17. Submitting_to_email (placeholder)
    features["Submitting_to_email"] = 1

    # 18. Abnormal_URL (placeholder)
    features["Abnormal_URL"] = 1

    # 19. Redirect (placeholder)
    features["Redirect"] = 1

    # 20. on_mouseover (placeholder)
    features["on_mouseover"] = 1

    # 21. RightClick (placeholder)
    features["RightClick"] = 1

    # 22. popUpWidnow (placeholder)
    features["popUpWidnow"] = 1

    # 23. Iframe (placeholder)
    features["Iframe"] = 1

    # 24. age_of_domain
    try:
        whois_info = whois.whois(domain)
        if isinstance(whois_info.creation_date, list):
            creation_date = whois_info.creation_date[0]
        else:
            creation_date = whois_info.creation_date
        if creation_date:
            age = (datetime.datetime.now() - creation_date).days
            features["age_of_domain"] = 1 if age >= 180 else -1
        else:
            features["age_of_domain"] = -1
    except:
        features["age_of_domain"] = -1

    # 25. DNSRecord (placeholder)
    features["DNSRecord"] = 1

    # 26. web_traffic (placeholder)
    features["web_traffic"] = 1

    # 27. Page_Rank (placeholder)
    features["Page_Rank"] = 1

    # 28. Google_Index (placeholder)
    features["Google_Index"] = 1

    # 29. Links_pointing_to_page (placeholder)
    features["Links_pointing_to_page"] = 1

    # 30. Statistical_report (placeholder)
    features["Statistical_report"] = 1

    return features
