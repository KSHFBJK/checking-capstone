import re
import math
import numpy as np
from urllib.parse import urlparse

CORE_BRANDS = [
    'google', 'facebook', 'microsoft', 'apple', 'paypal',
    'amazon', 'netflix', 'binance', 'instagram', 'twitter'
]

BAD_TLDS = ['.xyz','.top','.pw','.tk','.ml','.ga','.cf','.icu']


# =========================
# STABLE ENTROPY (FIXED)
# =========================
def get_entropy(s):
    if not s or len(s) < 2:
        return 0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


# =========================
# MAIN FEATURE ENGINE (30)
# =========================
def extract_features_from_url(url):

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    full = url.lower()

    main_domain = domain.split('.')[0] if domain else ""

    features = []

    # =========================
    # 1-5 BASIC STRUCTURE
    # =========================
    features.append(min(len(url)/100, 1))  # normalized URL length
    features.append(1 if any(x in url for x in ["bit.ly","tinyurl","t.co"]) else 0)
    features.append(1 if "@" in url else 0)
    features.append(1 if url.count("//") > 1 else 0)
    features.append(1 if "-" in domain else 0)

    # =========================
    # 6-10 DOMAIN STRUCTURE
    # =========================
    features.append(min(domain.count(".")/5, 1))
    features.append(1 if parsed.scheme == "https" else 0)
    features.append(1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain) else 0)
    features.append(1 if "https" in domain else 0)
    features.append(1 if parsed.port not in [None, 80, 443] else 0)

    # =========================
    # 11-15 KEYWORDS & PATTERNS
    # =========================
    phish_words = ["login","verify","secure","account","update","signin","confirm","password"]

    features.append(1 if any(w in full for w in phish_words) else 0)

    digit_ratio = sum(c.isdigit() for c in url) / len(url)
    features.append(min(digit_ratio, 1))

    specials = sum(url.count(c) for c in "-_?=&%")
    features.append(min(specials/10, 1))

    features.append(1 if ".com." in domain or ".net." in domain else 0)
    features.append(1 if re.search(r"\.(com|net|org)/", path) else 0)

    # =========================
    # 16-20 PATH ANALYSIS
    # =========================
    features.append(1 if "xn--" in domain else 0)
    features.append(min(len(path)/100, 1))
    features.append(min(len(query)/80, 1))
    features.append(1 if "#" in url else 0)
    features.append(1 if path.count(".") > 2 else 0)

    # =========================
    # 21-25 BEHAVIORAL RISK
    # =========================
    features.append(1 if any(x in path for x in ["pay","checkout","billing"]) else 0)
    features.append(1 if any(x in full for x in ["admin","client"]) else 0)
    features.append(min(domain.count(".")/5, 1))
    features.append(1 if any(domain.endswith(t) for t in BAD_TLDS) else 0)

    entropy_score = get_entropy(main_domain)
    features.append(min(entropy_score/5, 1))

    # =========================
    # 26-30 OBFUSCATION + BRAND
    # =========================
    features.append(min(len(domain)/30, 1))
    features.append(1 if url.count("_") > 3 else 0)
    features.append(1 if url.count("%") > 4 else 0)
    features.append(1 if re.search(r"(.)\1{3,}", url) else 0)

    # brand impersonation (SAFE FIX)
    brand_flag = 0
    for b in CORE_BRANDS:
        if b in main_domain and main_domain != b:
            brand_flag = 1
            break

    features.append(brand_flag)

    return np.array(features).reshape(1, -1)