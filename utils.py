import re

def detect_pattern(url):

    suspicious_words = [
        "login","verify","secure","update",
        "bank","account","auth","wallet"
    ]

    score = 0
    found = []

    for word in suspicious_words:
        if word in url.lower():
            score += 10
            found.append(word)

    if "-" in url:
        score += 5

    if len(url) > 70:
        score += 10

    return score, found
def early_warning(url_list):
    
    alerts = []

    for url in url_list:

        score, words = detect_pattern(url)

        if score >= 20:
            alerts.append({
                "url": url,
                "risk": score,
                "keywords": words
            })

    return alerts