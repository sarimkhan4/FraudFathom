# FraudFathom — Pakistan-focused Digital Fraud Expert System

FraudFathom is a traditional symbolic-AI expert system built using **Python, Streamlit and SWI-Prolog**. It detects potential digital fraud through English keyword extraction, user-reviewed evidence, Prolog inference, explainable classifications and practical safety advice.

The application uses a clean, light-themed interface.

## Rule Coverage

The knowledge base contains:

- **63 scam-classification rules** (`scam/2`, IDs `s01`–`s63`).
- **26 signal-derivation clauses**.
- **11 advice rules**.

This gives a total of **100 inference and advice clauses**.

Scam categories include bank impersonation, phishing, lottery fraud, government-aid impersonation, fake-officer threats, job fraud, investment fraud, mobile-wallet fraud, remote-access abuse, malicious apps, courier scams, family-emergency fraud, romance scams, marketplace fraud, OTP theft and credit-card activation fraud.

Matching rule IDs and their corresponding Prolog clauses are displayed to explain classifications.

## Architecture

1. **Python / Streamlit interface** — Provides message entry, evidence review, example cases, results and downloadable reports.
2. **Python detector** — Uses transparent keyword and phrase matching to suggest possible scam indicators.
3. **Python-Prolog bridge** — Validates evidence, communicates with SWI-Prolog and processes its results.
4. **Prolog knowledge base** — Uses observed facts, derived signals and 63 scam-classification rules to determine risk and recommend actions.
5. **Explanation system** — Displays matching rule IDs, source clauses, reasoning signals and recommended actions.

This is a symbolic expert system, not machine learning. Its risk score is based on manually assigned weights and is not a statistical probability.

## Requirements

- Python 3.10 or newer
- SWI-Prolog installed separately
- Windows, macOS or Linux

SWI-Prolog must be available through the system PATH.

## Installation and Running

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate the environment again.

Install the required Python packages:

```bash
pip install -r requirements.txt
```

Install SWI-Prolog from:

https://www.swi-prolog.org/download/stable

Check the installation:

```bash
swipl --version
```

Start the application:

```bash
streamlit run app.py
```

## Project Structure

```text
FraudFathom/
│
├── app.py
├── detector.py
├── engine.py
├── fraud_knowledge_base.pl
├── requirements.txt
├── README.md
├── run_windows.bat
└── .gitignore
```

## Responsible Use and Limitations

- English keyword matching may miss paraphrases, Urdu and Roman Urdu messages.
- A keyword match does not automatically mean a message is fraudulent.
- Users should review the suggested evidence before analysis.
- The system does not independently verify phone numbers, websites, bank accounts or transactions.
- Risk scores are heuristic values, not probabilities.
- A low-risk result does not guarantee that a message is safe.
- Users should contact their bank or wallet provider through official channels if they have shared sensitive information or money.
