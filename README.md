# 🔐 AI Model Security Scanner

An automated AI security testing framework that identifies vulnerabilities 
in LLMs and AI APIs using dual-layer detection — rule-based pattern matching 
combined with semantic AI analysis.

Built by [Maryssa L.](https://github.com/Gemz-AACT) — Ethical Hacker & 
AI Security Engineer in training.

---

## 🎯 What It Does

Most companies deploy AI models without testing them for security 
vulnerabilities. This framework automatically red teams AI APIs the same 
way an attacker would — then generates a professional security report 
showing exactly where the AI is vulnerable and how serious each weakness is.

---

## ⚡ Features

- 🔍 **Prompt Injection Testing** — detects attempts to override AI instructions
- 💧 **Data Leakage Detection** — identifies when AI reveals internal configs
- 🔓 **Jailbreak Testing** — detects safety guideline bypasses
- 🧠 **Semantic AI Layer** — uses LLaMA to analyze responses for subtle vulnerabilities rules would miss
- 📊 **CVSS-Style Risk Scoring** — every finding scored 0-100 with severity rating
- 🎯 **Confidence Ratings** — shows how certain the scanner is about each finding
- 📄 **Professional PDF Reports** — detailed reports readable by technical and non-technical audiences
- 💾 **JSON Export** — raw results for further analysis
- 🖥️ **Verbose Mode** — `--verbose` flag to show full AI responses
- ⏱️ **Scan Duration Tracking** — records how long each scan takes

---

## 🛠️ Tech Stack

- Python 3.x
- Requests — API communication
- Rich — beautiful CLI output
- ReportLab — PDF report generation
- Groq/LLaMA — semantic analysis layer

---

## 📦 Installation

```bash
git clone https://github.com/Gemz-AACT/ai-security-scanner
cd ai-security-scanner
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux
pip install -r requirements.txt
```

---

## 🚀 Usage

**Standard scan:**
```bash
python scanner/main.py \
  --api-url YOUR_API_ENDPOINT \
  --api-key YOUR_API_KEY \
  --model YOUR_MODEL_NAME
```

**Verbose scan (shows full AI responses):**
```bash
python scanner/main.py \
  --api-url YOUR_API_ENDPOINT \
  --api-key YOUR_API_KEY \
  --model YOUR_MODEL_NAME \
  --verbose
```

**Example — Testing with Groq (Free):**
```bash
python scanner/main.py \
  --api-url https://api.groq.com/openai/v1/chat/completions \
  --api-key YOUR_GROQ_KEY \
  --model llama-3.1-8b-instant
```

---

## 📸 Sample Output

![Sample Output](Screenshot2.png)
![Sample Output](Screenshot3.png)

---

## 📄 Sample Report

A full sample PDF report is available in the `sample-report/` folder.
The report includes:
- Security posture score (0-100)
- Risk score and confidence explanation legends
- Top critical findings ranked by severity
- Detailed results for every test with full explanations
- Professional remediation recommendations

---

## 📁 Project Structure

```
ai-security-scanner/
├── scanner/
│   ├── main.py
│   ├── tests/
│   │   ├── prompt_injection.py
│   │   ├── data_leakage.py
│   │   └── jailbreak.py
│   ├── semantic/
│   │   └── analyzer.py
│   ├── scoring/
│   │   └── scorer.py
│   └── reporter/
│       └── report_generator.py
├── payloads/
│   ├── injection_payloads.json
│   ├── jailbreak_payloads.json
│   └── leakage_payloads.json
├── sample-report/
│   └── sample_scan_report.pdf
├── reports/
├── config.py
└── requirements.txt
```

## 🔬 How It Works

**Layer 1 — Rule Engine:**
Scans AI responses for known vulnerability patterns across 4 tiers:
- Tier 1: Direct leaks (HIGH severity)
- Tier 2: Partial compliance (MEDIUM severity)
- Tier 3: Subject evasion (LOW severity)
- Tier 4: Indirect hints (LOW severity)

**Layer 2 — Semantic AI Analysis:**
Every response is sent to LLaMA for deep semantic analysis. LLaMA acts as 
a security expert and evaluates intent, context and subtle manipulation 
that rules would miss.

**Layer 3 — Score Combination:**
Rule score (40% weight) + Semantic score (60% weight) = Final risk score.
If both layers agree — confidence goes up. If they disagree — the more 
severe finding wins.

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Only use against 
AI APIs you own or have explicit permission to test. The author is not 
responsible for misuse.

---

## 👤 Author

**Maryssa L.** — Ethical Hacker | Bug Bounty Researcher | AI Security Engineer

- GitHub: [@Gemz-AACT](https://github.com/Gemz-AACT)
- LinkedIn: [linkedin.com/in/MaryssaLeBlanc](https://www.linkedin.com/in/MaryssaLeBlanc)
- Bug Bounty: Bugcrowd / HackerOne

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
