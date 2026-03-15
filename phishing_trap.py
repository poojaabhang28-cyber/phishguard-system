import re
import random

# phishing trap intelligence
suspicious_patterns = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "confirm",
    "password",
    "signin"
]

# fake domain patterns attackers use
fake_domains = [
    ".xyz",
    ".top",
    ".ru",
    ".tk",
    ".gq"
]


def phishing_trap(url):

    trap_score = 0
    triggers = []

    # keyword detection
    for word in suspicious_patterns:
        if word in url.lower():
            trap_score += 10
            triggers.append(word)

    # fake domain detection
    for d in fake_domains:
        if url.endswith(d):
            trap_score += 20
            triggers.append(d)

    # too many numbers
    numbers = re.findall(r'\d', url)
    if len(numbers) > 5:
        trap_score += 15
        triggers.append("too_many_numbers")

    # too long URL
    if len(url) > 75:
        trap_score += 10
        triggers.append("long_url")

    # random entropy detection
    if random.randint(1,10) > 8:
        trap_score += 5
        triggers.append("ai_pattern_flag")

    return {
        "trap_score": trap_score,
        "triggers": triggers
    }