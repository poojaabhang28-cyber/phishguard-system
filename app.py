from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from url_analyzer import analyze_url
from phishing_trap import phishing_trap
from werkzeug.security import generate_password_hash, check_password_hash
from deepweb_monitor import monitor_social_media, monitor_deep_web
import whois
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = "some_random_secure_key_here"
from flask import Flask, render_template, request
import sqlite3

app = Flask(__name__)

# -------- DATABASE SETUP --------

conn = sqlite3.connect("phishing.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans(
id INTEGER PRIMARY KEY AUTOINCREMENT,
url TEXT,
result TEXT,
risk INTEGER
)
""")

conn.commit()
conn.close()

# -------- DATABASE END --------

# ---------------- DATABASE END ----------------


# ---------------- URL FEATURES ----------------

def url_features(url):

    features = {}

    features["length"] = len(url)
    features["dots"] = url.count(".")
    features["hyphen"] = url.count("-")

    ip_pattern = r'\d+\.\d+\.\d+\.\d+'
    features["has_ip"] = bool(re.search(ip_pattern, url))

    return features


# ---------------- HTML FEATURES ----------------

def html_features(url):

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        forms = len(soup.find_all("form"))
        inputs = len(soup.find_all("input"))
        links = len(soup.find_all("a"))

        return {
            "forms": forms,
            "inputs": inputs,
            "links": links
        }

    except:
        return {
            "forms": 0,
            "inputs": 0,
            "links": 0
        }


# ---------------- KEYWORD CHECK ----------------

def keyword_check(url):

    words = ["login","verify","secure","bank","update","account"]

    found = []

    for w in words:
        if w in url.lower():
            found.append(w)

    return found


# ---------------- RISK CALCULATION ----------------

def calculate_risk(url):

    score = 0

    if not url.startswith("https"):
        score += 30

    if len(url) > 75:
        score += 10

    if "-" in url:
        score += 5

    suspicious_words = ["login","verify","secure","bank","update"]

    for w in suspicious_words:
        if w in url.lower():
            score += 10

    return score


# ---------------- DOMAIN AGE ----------------

def get_domain_age(url):

    try:

        domain = url.replace("https://","").replace("http://","").split("/")[0]

        w = whois.whois(domain)

        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.now() - creation_date).days

        return age_days

    except:
        return "Unknown"


# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ----------------- REGISTER -----------------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        conn = sqlite3.connect('phishing.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username,email,password) VALUES (?,?,?)",
                  (username,email,password))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

# ----------------- LOGIN -----------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('phishing.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]   # important
            return redirect(url_for('scan'))
        else:
            return "Invalid credentials"
    return render_template('login.html')

# ----------------- LOGOUT -----------------
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE result='Phishing' OR result='Suspicious'")
    phishing = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE result='Safe'")
    legit = cursor.fetchone()[0]

    conn.close()

    return render_template("dashboard.html", total=total, phishing=phishing, legit=legit)

# ---------------- HISTORY ----------------

@app.route("/history")
def history():

    conn = sqlite3.connect("phishing.db")
    c = conn.cursor()

    c.execute("SELECT url,result,risk FROM scans ORDER BY id DESC")

    data = c.fetchall()

    conn.close()

    return render_template("history.html", data=data)


# ---------------- PHISHING MAP ----------------

@app.route("/phishing-map")
def phishing_map():
    return render_template("phishing_map.html")


# ---------------- REPORT ----------------

@app.route("/report", methods=["GET","POST"])
def report():

    if request.method == "POST":

        url = request.form.get("url")
        result = request.form.get("result")
        risk = request.form.get("risk")

        # SAVE REPORT IN DATABASE
        conn = sqlite3.connect("phishing.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO scans(url,result,risk) VALUES (?,?,?)",
            (url, result, risk)
        )

        conn.commit()
        conn.close()

        return redirect("/history")

    return render_template("report.html")
# ----------------- SCAN -----------------
@app.route("/scan", methods=["GET","POST"])
def scan():

    if request.method == "POST":

        url = request.form.get("url")
        if not url:
            return "Error: URL not provided"

        username = request.form.get("username") or "testuser"

        # Detection functions
        trap = phishing_trap(url)
        analysis = analyze_url(url)
        features = url_features(url)
        html_data = html_features(url)
        keywords = keyword_check(url)

        risk = calculate_risk(url)

        result = "Safe" if risk < 30 else "Suspicious" if risk < 60 else "Phishing"

        domain_age = get_domain_age(url)

        # Social Media & Deep Web Monitoring
        social_mentions = monitor_social_media(username)
        deepweb_leaks = monitor_deep_web(username)

        # SAVE SCAN RESULT IN DATABASE
        conn = sqlite3.connect("phishing.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO scans(url,result,risk) VALUES (?,?,?)",
            (url, result, risk)
        )

        conn.commit()
        conn.close()

        return render_template(
            "scan_result.html",
            url=url,
            result=result,
            risk=risk,
            domain_age=domain_age,
            features=features,
            html_data=html_data,
            keywords=keywords,
            analysis=analysis,
            trap=trap,
            social_mentions=social_mentions,
            deepweb_leaks=deepweb_leaks
        )

    return render_template("scan_details.html")
# ---------------- THREAT MAP ----------------
@app.route('/threat-map')
def threat_map():
    """
    Renders the Threat Map page.
    This page is accessible to all users.
    Make sure 'templates/threat_map.html' exists.
    """
    return render_template('threat_map.html')

# ---------------- AI PREDICTION ----------------
@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"]

    score = 0
    if "login" in url:
        score += 20
    if "verify" in url:
        score += 20
    if "bank" in url:
        score += 30
    if "secure" in url:
        score += 20
    if len(url) > 70:
        score += 10

    if score < 30:
        result = "Safe Website"
    elif score < 60:
        result = "Suspicious Website"
    else:
        result = "Phishing Website"

    # Optional features for AI output page
    features = url_features(url)
    html_data = html_features(url)
    keywords = keyword_check(url)
    domain_age = "AI Prediction"

    return render_template(
        "ai_result.html",
        url=url,
        result=result,
        risk=score,
        domain_age=domain_age,
        features=features,
        html_data=html_data,
        keywords=keywords
    )
# ---------------- EARLY WARNING ----------------

@app.route("/early-warning")
def early_warning():

    test_urls = [
        "paytm-login-secure.com",
        "paytm-verify-user.net",
        "amazon-secure-login.org",
        "normalwebsite.com"
    ]

    from utils import early_warning

    alerts = early_warning(test_urls)

    return render_template(
        "early_warning.html",
        alerts=alerts
    )


# ---------------- ABOUT ----------------

@app.route("/about")
def about():
    return render_template("about.html")


# ---------------- RUN SERVER ----------------

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
