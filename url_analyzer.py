import re

# Advanced URL Analysis

def analyze_url(url):

    report = {}

    # URL Length
    report["length"] = len(url)

    # Number of dots
    report["dots"] = url.count(".")

    # Hyphen check
    report["hyphens"] = url.count("-")

    # IP address check
    ip_pattern = r'\d+\.\d+\.\d+\.\d+'
    report["has_ip"] = bool(re.search(ip_pattern, url))

    # Suspicious keywords
    keywords = ["login","verify","secure","bank","update","account"]

    found = []

    for word in keywords:
        if word in url.lower():
            found.append(word)

    report["keywords"] = found

    return report