# VulnLens AI 🔍

**AI-Powered Security Analysis and Vulnerability Explanation Platform**

VulnLens AI helps developers identify potential security vulnerabilities in their code and understand how to address them.

It combines static analysis tools with AI-powered explanations to make secure coding more accessible.

## ✨ Features

- **Bandit Integration:** Detects common security issues in Python code.
- **Semgrep Integration:** Performs rule-based static analysis across supported programming languages.
- **AI-Powered Explanations:** Uses Google Gemini to explain security findings, risks, and remediation.
- **Combined Security Reports:** Brings findings from multiple scanners into one dashboard.
- **Web Dashboard:** Provides a simple interface to scan projects and inspect findings.

## 🛠️ Technology Stack

- Python
- FastAPI
- Bandit
- Semgrep
- Google Gemini API
- HTML, CSS and JavaScript

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd VulnLens-AI
```

### 2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Install Semgrep separately if it is not included in your environment:

```bash
pipx install semgrep
```

### 4. Configure your API key

```bash
cp .env.example .env
```

Add your own Gemini API key to `.env`:

```env
GEMINI_API_KEY=your_actual_api_key
```

Never publish your API key.

### 5. Start VulnLens AI

```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Open http://127.0.0.1:8000 in your browser.

## 🔍 How It Works

1. Select a project directory.
2. Bandit and Semgrep analyze the code.
3. Findings are combined into a security report.
4. Gemini explains selected findings.
5. Developers receive guidance to understand and address security issues.

## ⚠️ Disclaimer

VulnLens AI is a development and educational security analysis tool. Static analysis cannot identify every vulnerability. Always manually review findings and validate suggested fixes before applying them.

## 🚀 Project Status

Active development — new features and improvements are planned.

## 👨‍💻 Author

Miles

---

**Making secure coding easier to understand.**
