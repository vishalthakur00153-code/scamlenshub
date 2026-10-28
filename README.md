# ScamLens

> **"Think Before You Trust. Scan Before You Pay."**

**ScamLens** is an open-source, educational safety tool designed to help students, job seekers, and everyday internet users assess suspicious messages and website links. It identifies red flags commonly found in **fraudulent internship offers, unexpected lottery prizes, urgent bank account threats, OTP harvesting schemes, and deceptive website addresses**.

ScamLens uses a **transparent, rule-based detection engine** running on Python and FastAPI. It does **not** rely on paid third-party AI APIs, does not send your data to external services, and does not require a database.

---

## Key Features

1. **Message Scanner**:
   - Analyzes pasted text for upfront fee requests (e.g., "refundable registration deposit" for an internship or laptop).
   - Detects artificial urgency and panic triggers (e.g., "account blocked in 2 hours").
   - Identifies credential harvesting (requests for OTPs, PINs, banking passwords).
   - Flags suspicious off-platform communication (e.g., conducting official hiring exclusively on Telegram or WhatsApp).
   - Highlights unrealistic compensation for trivial tasks (e.g., "earn $500 daily by liking videos").

2. **Structural URL Scanner (Non-Executing)**:
   - Evaluates links **offline** using structural heuristics without fetching or opening the target page.
   - Detects numeric IP addresses used as hostnames (e.g., `http://192.168.1.100/login`).
   - Flags brand impersonation and typosquatting in non-official domains (e.g., `paypal-security-verification.xyz`).
   - Identifies Punycode lookalike domains (`xn--...`) and embedded credentials (`http://bank.com@evil.com`).
   - Highlights URL shorteners that mask the true destination.

3. **Three-Tier Transparent Assessment**:
   - **Low Concern**: No prominent scam indicators detected (standard digital vigilance still applies).
   - **Needs Verification**: Cautionary indicators detected; independent verification recommended before taking action.
   - **Suspicious**: Multiple high-risk scam triggers identified; high likelihood of social engineering.

4. **Privacy & Transparency by Design**:
   - **Zero Storage**: Messages and links are analyzed in-memory and immediately discarded. Nothing is logged or written to disk.
   - **No Definitive Accusations**: Evaluates patterns and indicators objectively rather than making legally binding fraud claims based purely on keywords.
   - **Clear Limitations**: Always reminds users of rule-based boundaries and provides actionable safety steps.

---

## Technology Stack

- **Frontend**: HTML5, CSS3 (Modern dark-mode UI with responsive design), Vanilla JavaScript.
- **Backend**: Python 3.10+, FastAPI, Uvicorn (ASGI server), Pydantic v2 (Validation & Schemas).
- **Testing**: Pytest, HTTPX (TestClient).

---

## Project Structure

```text
scamlens/
├── app/
│   ├── __init__.py           # Package marker
│   ├── main.py               # FastAPI application & static file mounting
│   ├── models.py             # Pydantic data schemas & input validators
│   ├── engine.py             # Scoring algorithm, summaries, and action builder
│   └── rules/
│       ├── __init__.py
│       ├── message_rules.py  # Transparent regex rules for messages & offers
│       └── url_rules.py      # Structural rules for web links & domains
├── frontend/
│   ├── index.html            # Responsive single-page application
│   ├── styles.css            # Custom CSS design system
│   └── app.js                # Frontend controller & API client
├── tests/
│   ├── __init__.py
│   ├── test_api.py           # API endpoint & static asset tests
│   ├── test_message_scanner.py # Message rule unit tests (suspicious, legit, ambiguous)
│   ├── test_url_scanner.py     # URL rule unit tests (suspicious, legit, ambiguous)
│   └── test_edge_cases.py    # Edge case tests (empty input, whitespace, combined triggers)
├── .gitignore                # Python and IDE ignore patterns
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation and guide
```

---

## Getting Started on Windows

### Prerequisites

- Windows 10 or 11
- Python 3.10 or newer (tested with Python 3.14)
- PowerShell or Windows Terminal

### 1. Open PowerShell in the Project Directory

Open PowerShell and navigate to the project folder:

```powershell
cd C:\Users\Priyanka\scamlens
```

### 2. Activate the Virtual Environment

A virtual environment (`.venv`) is already configured in the folder. Activate it by running:

```powershell
.\.venv\Scripts\Activate.ps1
```

> *Tip: If PowerShell displays a script execution policy restriction, you can enable local scripts for the current session with:*
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> ```

*(Optional: If creating a fresh virtual environment from scratch on another machine)*:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Run Automated Tests

Verify that all tests pass:

```powershell
python -m pytest -v
```

You should see all 31 tests passing (`31 passed`).

### 4. Start the ScamLens Server

Run the application using Uvicorn:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Open ScamLens in Your Browser

Open your web browser (Chrome, Edge, Firefox) and visit:

**[http://127.0.0.1:8000](http://127.0.0.1:8000)**

You can also view interactive API documentation (Swagger UI) at:
**[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

---

## How to Test the Scanner

The ScamLens homepage includes one-click sample buttons so you can immediately see how different messages and links are analyzed:

### Message Scanner Examples
- **🎓 Internship Fee Scam**: Tests detection of upfront registration/laptop deposits and off-platform WhatsApp redirection. (Verdict: *Suspicious*)
- **🏦 Bank OTP Phishing**: Tests detection of urgent account freeze threats and demands for OTPs/PINs. (Verdict: *Suspicious*)
- **🎁 Lottery Jackpot**: Tests unsolicited prize claims and Telegram contact requests. (Verdict: *Suspicious*)
- **💼 Legitimate Offer**: Tests a normal email scheduling a technical interview. (Verdict: *Low Concern*)
- **🏷️ Flash Sale Deal**: Tests ambiguous marketing language with deep discounts. (Verdict: *Needs Verification*)

### URL Scanner Examples
- **⚠️ Raw IP Address**: `http://192.168.1.100:8080/secure/bank-login` (Verdict: *Suspicious*)
- **🎭 Brand & Credential Spoof**: `http://paypal-login-verify.example.com` (Verdict: *Suspicious* — flags brand 'paypal' and credentials in subdomain of unrelated domain 'example.com')
- **🔗 Shortened Link**: `https://bit.ly/3xFreePrizeNow` (Verdict: *Needs Verification*)
- **✅ Legitimate Portal**: `https://internshala.com/internships` (Verdict: *Low Concern*)
- **✅ Legitimate Brand Domain**: `https://www.paypal.com/signin` (Verdict: *Low Concern* — official domain verified)

---

## Safety & Educational Notice

ScamLens is an educational advisory tool. Its heuristic rules help spot warning signs, but cannot replace personal diligence:
- A verdict of **Low Concern** does not guarantee that a message or website is 100% safe.
- A verdict of **Suspicious** indicates that common social-engineering patterns are present, not a legal declaration of criminality.
- Always verify sensitive transactions directly with official organizations using verified phone numbers or official websites.
