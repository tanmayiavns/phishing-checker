from flask import Flask, render_template, request
import re

app = Flask(__name__)

def detect_phishing(url):
    score = 0
    reasons = []

    # 1. Length check
    if len(url) > 75:
        score += 2
        reasons.append("URL is too long")

    # 2. Too many dots
    if url.count('.') > 3:
        score += 2
        reasons.append("Too many subdomains")

    # 3. @ symbol
    if '@' in url:
        score += 3
        reasons.append("@ symbol detected (redirect trick)")

    # 4. Protocol
    if url.startswith("http://"):
        score += 2
        reasons.append("Uses HTTP (not secure)")
    elif not url.startswith("https://"):
        score += 1
        reasons.append("Unknown protocol")

    # 5. Suspicious keywords
    keywords = ["login", "verify", "update", "bank", "secure", "account"]
    for word in keywords:
        if word in url.lower():
            score += 2
            reasons.append(f"Suspicious word: {word}")

    # 6. Hyphen in domain
    if '-' in url:
        score += 1
        reasons.append("Hyphen in domain")

    # 7. Numbers in URL
    if re.search(r'\d+', url):
        score += 1
        reasons.append("Numbers in URL")

    # 8. IP address instead of domain
    if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
        score += 3
        reasons.append("Uses IP address instead of domain")

    # 9. Redirection (//)
    if url.count("//") > 1:
        score += 2
        reasons.append("Multiple // (possible redirect)")

    # Final decision
    if score >= 8:
        result = "Phishing 🚨"
    elif score >= 4:
        result = "Suspicious ⚠️"
    else:
        result = "Safe ✅"

    return result, score, reasons


@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    score = 0
    reasons = []

    if request.method == "POST":
        url = request.form["url"]
        result, score, reasons = detect_phishing(url)

    return render_template("index.html", result=result, score=score, reasons=reasons)


if __name__ == "__main__":
    app.run(debug=True)