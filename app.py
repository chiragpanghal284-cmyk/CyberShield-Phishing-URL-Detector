"""
CyberShield – Flask Web Application
Serves the phishing URL detection dashboard.

SAFETY NOTICE:
  - URLs are analysed locally using heuristics only.
  - No URL is fetched, visited, or sent to any external service.
  - No personal data, passwords, or cookies are collected.
"""

from flask import Flask, render_template, request, jsonify, session
from detector import analyze_url
import datetime

app = Flask(__name__)
# Secret key required for session storage (scan history lives in the session)
app.secret_key = "cybershield-local-dev-key-change-in-production"


@app.route("/")
def index():
    if "history" not in session:
        session["history"] = []
    return render_template("index.html", history=session["history"])


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    result = analyze_url(url)
    result["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Persist to session history (max 20 entries, newest first)
    if "history" not in session:
        session["history"] = []

    history = session["history"]
    history.insert(0, {
        "url": result["url"],
        "category": result["category"],
        "score": result["score"],
        "timestamp": result["timestamp"],
    })
    session["history"] = history[:20]
    session.modified = True

    return jsonify(result)


@app.route("/clear-history", methods=["POST"])
def clear_history():
    session["history"] = []
    session.modified = True
    return jsonify({"status": "cleared"})


if __name__ == "__main__":
    # Debug mode is intentionally left ON for local development only.
    # Set debug=False before any public deployment.
    app.run(debug=True, port=5000)
