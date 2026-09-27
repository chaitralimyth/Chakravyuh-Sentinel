"""
Deterministic URL feature extraction.

IMPORTANT:
The feature names/order come from features-order.pkl.

Every feature used by the model must have a deterministic
calculation. Random values MUST NOT be used.
"""

import ipaddress
import re
from urllib.parse import urlparse
from app.model_loader import feature_order

def is_ip(domain: str) -> int:
    try:
        ipaddress.ip_address(domain)
        return 1

    except ValueError:
        return 0

def extract_features(url: str) -> list:
    """
    Extract URL features in the exact order required
    by features-order.pkl.
    """

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")
    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    url_lower = url.lower()
    parsed = urlparse(
        url if "://" in url else "http://" + url
    )
    domain = parsed.netloc.split("@")[-1].split(":")[0]
    url_length = len(url)
    safe_length = max(url_length, 1)

    # ---------------------------------------------------------
    # Basic features
    # ---------------------------------------------------------

    features = {}
    features["URLLength"] = url_length
    features["DomainLength"] = len(domain)
    features["NumDots"] = url.count(".")
    features["IsDomainIP"] = is_ip(domain)

    # ---------------------------------------------------------
    # Character features
    # ---------------------------------------------------------

    letters = sum(
        char.isalpha()
        for char in url
    )

    digits = sum(
        char.isdigit()
        for char in url
    )

    special_chars = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url,
        )
    )

    features["NoOfLettersInURL"] = letters
    features["NoOfDegitsInURL"] = digits
    features["LetterRatioInURL"] = (
        letters / safe_length
    )
    features["DegitRatioInURL"] = (
        digits / safe_length
    )
    features["NoOfOtherSpecialCharsInURL"] = (
        special_chars
    )
    features["SpacialCharRatioInURL"] = (
        special_chars / safe_length
    )

    # ---------------------------------------------------------
    # Suspicious keywords
    # ---------------------------------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "bank",
        "paypal",
        "update",
        "confirm",
        "warning",
        "free",
        "gift",
        "card",
        "win",
        "prize",
        "offer",
        "amazon",
        "google",
        "facebook",
    ]

    keyword_score = sum(
        word in url_lower
        for word in suspicious_keywords
    )

    features["Bank"] = int(
        "bank" in url_lower
    )

    features["Pay"] = int(
        "pay" in url_lower
        or "paypal" in url_lower
    )

    features["Crypto"] = int(
        "crypto" in url_lower
    )

    features["URLSimilarityIndex"] = min(
        1.0,
        0.2 + 0.15 * keyword_score,
    )

    # ---------------------------------------------------------
    # Domain / subdomain
    # ---------------------------------------------------------

    features["NoOfSubDomain"] = max(
        0,
        domain.count(".") - 1,
    )

    # ---------------------------------------------------------
    # HTTPS
    # ---------------------------------------------------------

    features["IsHTTPS"] = int(
        parsed.scheme.lower() == "https"
    )

    # ---------------------------------------------------------
    # Obfuscation
    # ---------------------------------------------------------

    obfuscated_chars = (
        url.count("%")
        + url.count("@")
    )

    features["HasObfuscation"] = int(
        "@" in url
        or "%" in url
    )

    features["NoOfObfuscatedChar"] = (
        obfuscated_chars
    )

    features["ObfuscationRatio"] = (
        obfuscated_chars / safe_length
    )

    # ---------------------------------------------------------
    # TLD
    # ---------------------------------------------------------

    suspicious_tlds = (
        ".xyz",
        ".tk",
        ".ru",
        ".ml",
        ".ga",
        ".click",
    )

    domain_lower = domain.lower()
    features["TLDLegitimateProb"] = (
        0.2
        if any(
            domain_lower.endswith(tld)
            for tld in suspicious_tlds
        )
        else 0.9
    )

    # ---------------------------------------------------------
    # Validate every model feature
    # ---------------------------------------------------------

    missing_features = [
        feature
        for feature in feature_order
        if feature not in features
    ]

    if missing_features:

        raise RuntimeError(
            "The URL feature extractor does not implement "
            "the following features required by "
            "features-order.pkl:\n"
            + "\n".join(
                f"- {feature}"
                for feature in missing_features
            )
        )

    # ---------------------------------------------------------
    # Exact training order
    # ---------------------------------------------------------

    return [
        features[name]
        for name in feature_order
    ]