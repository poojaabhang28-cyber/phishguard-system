import requests
from bs4 import BeautifulSoup

def monitor_social_media(username):
    """
    Monitor public social media mentions of a username
    Returns a list of suspicious mentions
    """
    results = []

    # Example: search Twitter or public forums
    # (replace with actual API or scraping logic)
    try:
        search_url = f"https://twitter.com/search?q={username}"
        resp = requests.get(search_url)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            tweets = soup.find_all('div', {'data-testid':'tweet'})
            for tweet in tweets[:5]:  # check first 5
                results.append(tweet.text)
    except:
        results.append("Social media monitoring error")

    return results

def monitor_deep_web(username):
    """
    Scan deep web / forums for leaked credentials or mentions
    Returns list of detected leaks
    """
    leaks = []
    # Example: search Pastebin / hacker forums
    # (replace with actual scraping or API)
    try:
        pastebin_url = f"https://pastebin.com/search?q={username}"
        resp = requests.get(pastebin_url)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            entries = soup.find_all('div', {'class':'gsc-thumbnail-inside'})
            for e in entries[:5]:
                leaks.append(e.text)
    except:
        leaks.append("Deep web monitoring error")

    return leaks