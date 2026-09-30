"""
Deterministic URL feature extraction.
Extracts features according to the exact schema and ordering in features-order.pkl.
"""

import ipaddress
import re
from urllib.parse import urlparse
from app.model_loader import feature_order


def is_ip(domain: str) -> int:
    try:
        ipaddress.ip_address(domain)
        return 1
    except (ValueError, Exception):
        return 0


def extract_features(url: str) -> list:
    """
    Extract URL features in the exact order required by features-order.pkl.
    Deterministic: no random number generation.
    """
    if not isinstance(url, str):
        raise ValueError("URL must be a string.")
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")

    url_lower = url.lower()
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.split("@")[-1].split(":")[0] if parsed.netloc else url.split("/")[0]
    url_length = len(url)
    safe_length = max(url_length, 1)

    features = {}

    # Basic features
    features["URLLength"] = url_length
    features["DomainLength"] = len(domain)
    features["NumDots"] = url.count(".")
    features["IsDomainIP"] = is_ip(domain)

    # Character-based features
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    special_chars = len(re.findall(r"[^a-zA-Z0-9]", url))

    features["NoOfLettersInURL"] = letters
    features["NoOfDegitsInURL"] = digits
    features["LetterRatioInURL"] = letters / safe_length
    features["DegitRatioInURL"] = digits / safe_length
    features["NoOfOtherSpecialCharsInURL"] = special_chars
    features["SpacialCharRatioInURL"] = special_chars / safe_length

    # Punctuation counts
    features["NoOfEqualsInURL"] = url.count("=")
    features["NoOfQMarkInURL"] = url.count("?")
    features["NoOfAmpersandInURL"] = url.count("&")

    # Keyword indicators
    suspicious_keywords = [
        "login", "verify", "secure", "account",
        "bank", "paypal", "update", "confirm", "warning",
        "free", "gift", "card", "win", "prize", "offer",
        "amazon", "google", "facebook",
    ]
    keyword_score = sum(word in url_lower for word in suspicious_keywords)

    features["Bank"] = int("bank" in url_lower)
    features["Pay"] = int("pay" in url_lower or "paypal" in url_lower)
    features["Crypto"] = int("crypto" in url_lower)
    features["URLSimilarityIndex"] = min(1.0, 0.2 + 0.15 * keyword_score)

    # Domain / Subdomain / Scheme
    features["NoOfSubDomain"] = max(0, domain.count(".") - 1)
    features["IsHTTPS"] = int(parsed.scheme.lower() == "https")

    # Obfuscation
    obfuscated_chars = url.count("%") + url.count("@")
    features["HasObfuscation"] = int("@" in url or "%" in url)
    features["NoOfObfuscatedChar"] = obfuscated_chars
    features["ObfuscationRatio"] = obfuscated_chars / safe_length

    # TLD
    suspicious_tlds = [".xyz", ".tk", ".ru", ".ml", ".ga", ".click"]
    domain_lower = domain.lower()
    features["TLDLegitimateProb"] = 0.2 if any(domain_lower.endswith(tld) for tld in suspicious_tlds) else 0.9
    parts = domain.rsplit(".", 1)
    features["TLDLength"] = len(parts[-1]) if len(parts) > 1 else 0

    # Deterministic character continuation and probability heuristics
    features["CharContinuationRate"] = 0.0
    features["URLCharProb"] = 0.5

    # Page/DOM features: for raw URL inputs, these are deterministically defaulted to 0.0
    page_features = [
        "LineOfCode", "LargestLineLength", "HasTitle", "DomainTitleMatchScore",
        "URLTitleMatchScore", "HasFavicon", "Robots", "IsResponsive",
        "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription", "NoOfPopup",
        "NoOfiFrame", "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton",
        "HasHiddenFields", "HasPasswordField", "HasCopyrightInfo", "NoOfImage",
        "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef"
    ]
    for pf in page_features:
        features[pf] = 0.0

    return [float(features.get(f, 0.0)) for f in feature_order]
