import re
import ipaddress
import random
from urllib.parse import urlparse
from app.model_loader import feature_order


def is_ip(domain):
    try:
        ipaddress.ip_address(domain)
        return 1
    except:
        return 0


def extract_features(url: str):
    url_lower = url.lower()
    domain = urlparse(url).netloc if "://" in url else url.split('/')[0]

    # 🔹 Basic real features
    features = {
        "URLLength": len(url),
        "DomainLength": len(domain),
        "NumDots": url.count('.'),
        "IsDomainIP": is_ip(domain),
    }

    # 🔹 Character-based
    features["NoOfLettersInURL"] = sum(c.isalpha() for c in url)
    features["NoOfDegitsInURL"] = sum(c.isdigit() for c in url)
    features["LetterRatioInURL"] = features["NoOfLettersInURL"] / len(url)
    features["DegitRatioInURL"] = features["NoOfDegitsInURL"] / len(url)

    special_chars = len(re.findall(r'[^a-zA-Z0-9]', url))
    features["NoOfOtherSpecialCharsInURL"] = special_chars
    features["SpacialCharRatioInURL"] = special_chars / len(url)

    # 🔹 Keyword-based simulation (FIXED INDENT)
    suspicious_keywords = [
        "login", "verify", "secure", "account",
        "bank", "paypal", "update", "confirm", "warning",
        "free", "gift", "card", "win", "prize", "offer",
        "amazon", "google", "facebook"
    ]

    features["Bank"] = int("bank" in url_lower)
    features["Pay"] = int("pay" in url_lower or "paypal" in url_lower)
    features["Crypto"] = int("crypto" in url_lower)

    keyword_score = sum(word in url_lower for word in suspicious_keywords)

    # 🔹 URL similarity (fake but smart)
    features["URLSimilarityIndex"] = min(1.0, 0.2 + 0.15 * keyword_score)

    # 🔹 Subdomain logic
    features["NoOfSubDomain"] = max(0, domain.count('.') - 1)

    # 🔹 HTTPS
    features["IsHTTPS"] = int(url.startswith("https"))

    # 🔹 Obfuscation simulation
    features["HasObfuscation"] = int("@" in url or "%" in url)
    features["NoOfObfuscatedChar"] = url.count('%') + url.count('@')
    features["ObfuscationRatio"] = features["NoOfObfuscatedChar"] / len(url)

    # 🔹 TLD risk simulation
    suspicious_tlds = [".xyz", ".tk", ".ru", ".ml", ".ga", ".click"]
    features["TLDLegitimateProb"] = 0.2 if any(url.endswith(tld) for tld in suspicious_tlds) else 0.9

    # 🔹 Fallback for ALL remaining features
    final_features = []
    for f in feature_order:
        if f in features:
            final_features.append(features[f])
        else:
            final_features.append(random.uniform(0.1, 0.9))

    return final_features