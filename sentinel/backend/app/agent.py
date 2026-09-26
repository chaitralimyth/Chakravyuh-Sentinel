def decide(score, url):
    url_lower = url.lower()

    reasons = []

    # 🔴 keyword detection
    suspicious_keywords = [
        "login", "verify", "secure", "account",
        "bank", "paypal", "update", "confirm",
        "free", "gift", "win", "urgent"
    ]

    keyword_hits = sum(word in url_lower for word in suspicious_keywords)

    if keyword_hits >= 2:
        reasons.append("Multiple suspicious keywords")

    # 🔴 risky TLD
    risky_tlds = [".xyz", ".tk", ".ru", ".ml", ".ga", ".click"]
    if any(url_lower.endswith(tld) for tld in risky_tlds):
        reasons.append("Suspicious domain extension")

    # 🔴 brand misuse
    brands = ["google", "facebook", "amazon", "paypal", "bank"]
    if any(b in url_lower for b in brands) and keyword_hits >= 1:
        reasons.append("Brand impersonation")

    # 🚨 FINAL DECISION LOGIC

    # STRONG BLOCK CONDITION
    if keyword_hits >= 2 and any(tld in url_lower for tld in risky_tlds):
        return "BLOCK", reasons

    if "Brand impersonation" in reasons and "Suspicious domain extension" in reasons:
        return "BLOCK", reasons

    # MEDIUM
    if keyword_hits >= 1 or "Suspicious domain extension" in reasons:
        return "ALERT", reasons

    # ML fallback
    if score > 0.7:
        return "BLOCK", ["High ML confidence"]
    elif score > 0.4:
        return "ALERT", ["Moderate ML confidence"]

    return "ALLOW", ["No strong threat indicators"]