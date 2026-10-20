# 🛡 CyberShield – Phishing URL Detection System

> **Educational tool only.** CyberShield uses heuristic rules to estimate how suspicious a URL looks. It **cannot** guarantee whether a URL is safe or malicious. Always verify links through official channels.

---

## What is CyberShield?

CyberShield is a beginner-friendly cybersecurity web application that analyses a URL's structure for common phishing indicators. It assigns a **risk score** and categorises the result as **Low**, **Medium**, or **High** risk, then explains every warning sign in plain language.

All analysis happens **locally on your machine** — no URL is fetched, visited, or sent to any external service.

---

## Features

| Feature | Details |
|---------|---------|
| URL format validation | Rejects blank or malformed inputs immediately |
| IP hostname detection | Flags raw IP addresses used as hostnames |
| URL length check | Warns when URLs exceed 100 characters |
| @ symbol check | Detects the `@` trick that tricks browsers into ignoring the real domain |
| Subdomain depth | Flags suspiciously deep subdomain nesting |
| Keyword analysis | Spots words like `login`, `verify`, `password`, `paypal` in the URL |
| HTTPS check | Notes when plain HTTP is used instead of HTTPS |
| Hyphen-in-domain | Catches `pay-pal.com`-style brand spoofing |
| Double-slash redirect | Detects `//` in the URL path |
| Risk score & category | Aggregated Low / Medium / High verdict with explanations |
| Scan history | Last 20 scans stored in your browser session |
| Unit tests | 20+ tests covering valid, invalid, and suspicious URLs |

---

## Project Structure

```
CyberShield/
├── app.py                  # Flask web application
├── detector.py             # Heuristic URL analysis engine
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── templates/
│   └── index.html          # Dashboard UI (Jinja2 template)
├── static/
│   └── style.css           # Dark-theme cybersecurity stylesheet
└── tests/
    └── test_detector.py    # Unit tests (Python unittest)
```

---

## Installation & Setup (Windows)

### Prerequisites

- Python 3.10 or later — download from [python.org](https://www.python.org/downloads/)
- pip (bundled with Python)

### Step-by-step

**1. Open PowerShell** (or Command Prompt) and navigate to the project folder:

```powershell
cd "C:\Users\<YourName>\Documents\GTA Vice City User Files"
```

**2. Create a virtual environment** (recommended — keeps dependencies isolated):

```powershell
python -m venv venv
```

**3. Activate the virtual environment:**

```powershell
.\venv\Scripts\Activate.ps1
```

> If you see a script execution policy error, run:
> `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
> then try again.

**4. Install dependencies:**

```powershell
pip install -r requirements.txt
```

**5. Start the application:**

```powershell
python app.py
```

**6. Open your browser** and go to:

```
http://127.0.0.1:5000
```

---

## Running the Tests

With the virtual environment active, run from the project root:

```powershell
python -m pytest tests/ -v
```

Or using the built-in unittest runner (no extra install needed):

```powershell
python -m unittest discover -s tests -v
```

All tests use only harmless, fictitious URLs and run entirely offline.

---

## Usage

1. Type or paste a URL into the text box (it must start with `http://` or `https://`).
2. Click **Scan**.
3. Read the **risk level**, **score**, and the list of **reasons**.
4. Check the **Scan History** section below to review past URLs.

---

## How Risk Scores Work

| Score | Category | Meaning |
|-------|----------|---------|
| 0 | Low | No warning signs detected |
| 1–3 | Medium | One or more mild warning signs |
| 4+ | High | Multiple or serious red flags |

Each rule contributes a weight:

| Rule | Weight |
|------|--------|
| IP address as hostname | 3 |
| `@` symbol in host part | 3 |
| URL length > 100 chars | 2 |
| More than 4 subdomain levels | 2 |
| Double `//` in path | 2 |
| Suspicious keyword in URL | 1 |
| HTTP instead of HTTPS | 1 |
| Hyphen in domain | 1 |

---

## Safety & Privacy

- **No network requests.** CyberShield never fetches or visits any URL you enter.
- **No data collection.** No passwords, cookies, or personal information are stored.
- **Local session only.** Scan history lives in your browser's session cookie and is cleared when you close the tab or click *Clear*.
- **No definitive verdicts.** Heuristic analysis cannot replace professional security tooling.

---

## Limitations

- **False positives:** Legitimate sites may score Medium or High (e.g. a long HTTPS URL with many subdomains).
- **False negatives:** A sophisticated phishing URL that passes all heuristic checks will score Low.
- **No content analysis:** The page content is never fetched; only the URL string is examined.
- **No reputation lookup:** There is no integration with threat-intel feeds or blocklists.

---

## Future Improvements

- [ ] Integrate the [Google Safe Browsing API](https://safebrowsing.google.com/) for reputation checks.
- [ ] Add WHOIS lookup to flag recently registered domains.
- [ ] Support bulk URL scanning via file upload.
- [ ] Export scan history as CSV.
- [ ] Add a browser extension wrapper.
- [ ] Implement machine-learning scoring using a labelled phishing dataset.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask |
| Frontend | HTML5, CSS3 (dark theme) |
| Testing | Python `unittest` |
| Dependencies | Flask only (see `requirements.txt`) |

---

## License

This project is released for educational purposes. Use responsibly.
