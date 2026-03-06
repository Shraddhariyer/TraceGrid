from datetime import datetime


def calculate_risk(whois_data, dns_data, ssl_domains, wayback_data=None, cluster_size=0):
    score = 0
    reasons = []

    domain_name = whois_data.get("domain", "").lower()

    # 🔴 1. Domain Age Check
    creation_date = whois_data.get("creation_date")

    try:
        if creation_date:
            creation_date = datetime.fromisoformat(creation_date.replace("Z", ""))
            age_days = (datetime.now() - creation_date).days

            if age_days < 30:
                score += 40
                reasons.append("Extremely new domain (<30 days)")

            elif age_days < 90:
                score += 25
                reasons.append("Very new domain (<90 days)")

            elif 90 <= age_days <= 730:
                score += 20
                reasons.append("Moderately aged domain (common in fraud infra)")

    except:
        pass

    # 🔴 2. Missing WHOIS
    if not whois_data.get("registrar"):
        score += 20
        reasons.append("Missing registrar info")

    # 🔴 3. Too many IPs (Fast Flux)
    ip_list = dns_data.get("ip_addresses", [])

    if ip_list:
        ip_count = len(ip_list)

        if ip_count > 5:
            score += 20
            reasons.append("High number of IPs (possible fast-flux)")

        elif ip_count > 3:
            score += 10
            reasons.append("Multiple IPs")

    # 🔴 4. SSL Spread
    if len(ssl_domains) > 20:
        score += 25
        reasons.append("Large SSL cluster (shared infra)")

    elif len(ssl_domains) > 10:
        score += 15
        reasons.append("Shared SSL with many domains")

    # 🔴 5. Suspicious TLD
    if domain_name.endswith((
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click"
    )):
        score += 25
        reasons.append("Suspicious TLD")

    # 🔴 6. Suspicious Keywords
    suspicious_keywords = [
        "bet", "win", "casino", "play", "poker", "slot", "jackpot",
        "cash", "bonus", "reward", "earn", "profit", "income",
        "verify", "secure", "update", "login", "account", "auth",
        "free", "gift", "offer", "deal", "promo", "claim",
        "crypto", "btc", "bitcoin", "investment", "loan", "trading",
        "apk", "download", "app", "mod", "hack"
    ]

    keyword_flag = False

    for word in suspicious_keywords:
        if word in domain_name:
            score += 30
            reasons.append(f"Suspicious keyword detected: {word} (high-risk category)")
            keyword_flag = True
            break

    # 🔴 7. Cloud Hosting Detection
    cloud_flag = False

    for ip in ip_list:
        if ip.startswith(("13.", "16.", "3.", "18.", "34.", "35.")):
            score += 15
            reasons.append("Hosted on cloud infrastructure (possible abuse)")
            cloud_flag = True
            break

    # 🔴 8. Combined Signals
    if keyword_flag and cloud_flag:
        score += 20
        reasons.append("Keyword + cloud infra combination (high abuse pattern)")

    # 🔴 9. Cluster Detection (NEW — VERY POWERFUL)
    if cluster_size > 30:
        score += 30
        reasons.append("Part of large domain cluster (possible fraud network)")

    elif cluster_size > 15:
        score += 20
        reasons.append("Part of medium-sized cluster")

    elif cluster_size > 5:
        score += 10
        reasons.append("Connected to multiple related domains")

    # 🔴 10. Wayback Signal
    if wayback_data and wayback_data.get("status") == "ok":
        snapshots = wayback_data.get("snapshot_count", 0)

        if snapshots == 0:
            score += 10
            reasons.append("No history (weak signal)")

        elif snapshots < 5:
            score += 5
            reasons.append("Very little history")

        elif snapshots > 50:
            score -= 10
            reasons.append("Old domain with strong history")

    # 🔴 11. Final Score Clamp
    score = max(0, min(score, 100))

    return {
        "score": score,
        "reasons": reasons
    }