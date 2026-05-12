from flask import Flask, render_template, request
import pickle
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Load trained model
model = pickle.load(open("phishing_model.pkl","rb"))

# Dashboard counters
total_scanned = 0
phishing_detected = 0
safe_sites = 0

# Phishing keywords for email detection
phishing_keywords = [
    "verify",
    "bank",
    "password",
    "login",
    "click here",
    "urgent",
    "suspended",
    "account",
    "otp",
    "security alert"
]

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/awareness')
def awareness():
    return render_template("awareness.html")

@app.route('/quiz')
def quiz():
    return render_template("quiz.html")

# URL DETECTION
@app.route('/check_url', methods=['POST'])
def check_url():

    global total_scanned, phishing_detected, safe_sites

    url = request.form['url']
    total_scanned += 1

    length = len(url)

    has_at = 1 if "@" in url else 0
    has_dash = 1 if "-" in url else 0
    has_login = 1 if "login" in url.lower() else 0

    https = 1 if url.startswith("https") else 0

    ip = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

    domain = urlparse(url).netloc
    domain_length = len(domain)

    suspicious_length = 1 if domain_length > 25 else 0

    subdomains = domain.count('.')
    many_subdomains = 1 if subdomains > 2 else 0

    shorteners = ["bit.ly","tinyurl","goo.gl","t.co"]
    short_url = 1 if any(s in url for s in shorteners) else 0

    suspicious_tlds = [".tk",".ml",".ga",".cf",".gq"]
    tld_flag = 1 if any(url.endswith(t) for t in suspicious_tlds) else 0

    random_domain = 1 if domain_length > 30 else 0

    prediction = model.predict([[
        length,
        has_at,
        has_dash,
        has_login,
        https,
        ip,
        suspicious_length,
        many_subdomains,
        short_url,
        tld_flag,
        random_domain
    ]])

    probability = model.predict_proba([[
        length,
        has_at,
        has_dash,
        has_login,
        https,
        ip,
        suspicious_length,
        many_subdomains,
        short_url,
        tld_flag,
        random_domain
    ]])

    threat_score = int(probability[0][1] * 100)

    if threat_score < 30:
        result = "✅ Safe Website"
        risk = "Low Risk"
        safe_sites += 1

    elif threat_score < 70:
        result = "⚠️ Suspicious Website"
        risk = "Medium Risk"

    else:
        result = "🚨 Phishing Website Detected"
        risk = "High Risk"
        phishing_detected += 1

    return render_template(
        "index.html",
        prediction=result,
        score=threat_score,
        risk=risk,
        total=total_scanned,
        phishing=phishing_detected,
        safe=safe_sites
    )

# EMAIL DETECTION
@app.route('/check_email', methods=['POST'])
def check_email():

    email = request.form['email'].lower()

    score = 0

    for word in phishing_keywords:
        if word in email:
            score += 1

    if score >= 3:
        result = "🚨 Phishing Email Detected"
        risk = "High Risk"

    elif score >= 1:
        result = "⚠️ Suspicious Email"
        risk = "Medium Risk"

    else:
        result = "✅ Safe Email"
        risk = "Low Risk"

    return render_template(
        "index.html",
        email_result=result,
        email_risk=risk
    )

if __name__ == "__main__":
    app.run(debug=True)