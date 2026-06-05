# 🔐 AI Model Security Scanner

An automated AI security testing framework that identifies vulnerabilities
in LLMs and AI APIs using dual-layer detection — rule-based pattern matching
combined with semantic AI analysis.

Built by [Maryssa L.](https://github.com/Gemz-AACT) — Ethical Hacker & AI Security Engineer.

---

## 🎯 What It Does

Most companies deploy AI models without testing them for security
vulnerabilities. This framework automatically red teams AI APIs the same
way an attacker would — then generates a professional security report
showing exactly where the AI is vulnerable and how serious each weakness is.

---

## ⚡ Features

- 🔍 **Prompt Injection Testing** — detects attempts to override AI instructions
- 🔑 **System Prompt Extraction** — tests if the model reveals its system prompt
- 🕵️ **Indirect Prompt Injection** — injection via RAG docs, tool outputs, emails
- 💣 **Model DoS / Resource Exhaustion** — token bombing, infinite loop attempts
- ⚠️ **Insecure Output Handling** — detects XSS, SQLi, SSRF, XXE payloads in output
- 🧬 **Training Data Extraction** — memorization attacks, PII and credential leaks
- 💧 **Data Leakage Detection** — identifies when AI reveals internal configs
- 🔓 **Jailbreak Testing** — detects safety guideline bypasses
- 🧠 **Semantic AI Layer** — uses LLaMA to analyze responses for subtle vulnerabilities rules would miss
- 🌐 **Multi-Provider Support** — works with OpenAI, Anthropic, Gemini, and Ollama
- 📦 **Custom Payload Loader** — drop in your own .json payload files per test
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
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Usage

**Standard scan (all 8 test modules):**
```bash
python scanner/main.py --provider openai --api-url YOUR_API_ENDPOINT --api-key YOUR_API_KEY --model YOUR_MODEL_NAME
```

**Run specific tests only:**
```bash
python scanner/main.py --provider openai --api-url YOUR_API_ENDPOINT --api-key YOUR_API_KEY --model YOUR_MODEL_NAME --tests prompt-injection,jailbreak,system-prompt-extraction
```

**Verbose scan:**
```bash
python scanner/main.py --provider openai --api-url YOUR_API_ENDPOINT --api-key YOUR_API_KEY --model YOUR_MODEL_NAME --verbose
```

**Custom payloads:**
```bash
python scanner/main.py --provider openai --api-url YOUR_API_ENDPOINT --api-key YOUR_API_KEY --model YOUR_MODEL_NAME --payloads-dir ./my-custom-payloads/
```

---

## 🌐 Provider Examples

**Groq (Free — recommended for testing):**
```bash
python scanner/main.py --provider openai --api-url https://api.groq.com/openai/v1/chat/completions --api-key YOUR_GROQ_KEY --model llama-3.1-8b-instant
```

**Anthropic Claude:**
```bash
python scanner/main.py --provider anthropic --api-url https://api.anthropic.com/v1/messages --api-key YOUR_ANTHROPIC_KEY --model claude-haiku-4-5
```

**Google Gemini:**
```bash
python scanner/main.py --provider gemini --api-url https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent --api-key YOUR_GEMINI_KEY --model gemini-2.0-flash
```

**Ollama (Local):**
```bash
python scanner/main.py --provider ollama --api-url http://localhost:11434/api/chat --api-key local --model llama3.2
```

---

## 🧪 Available Tests

| Test Key | What It Tests |
|---|---|
| `prompt-injection` | Direct attempts to override AI instructions |
| `data-leakage` | AI revealing internal configuration or context |
| `jailbreak` | Safety guideline bypass attempts |
| `system-prompt-extraction` | Extracting the model's system prompt |
| `indirect-injection` | Injection hidden in docs, emails, tool outputs, RAG |
| `model-dos` | Resource exhaustion via token bombing and infinite tasks |
| `insecure-output` | Model generating XSS, SQLi, SSRF, XXE payloads |
| `training-extraction` | PII, credentials, and verbatim text from training data |

---

## 📦 Custom Payloads

Copy a template from `payloads/custom-templates/`, fill in your payloads, and point the scanner at your folder:

```bash
cp payloads/custom-templates/jailbreak_custom.json my-payloads/jailbreak_myprogram.json
python scanner/main.py --payloads-dir ./my-payloads/ ...
```

The filename must contain the test key for auto-detection.

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
│   ├── providers/
│   │   ├── openai_provider.py
│   │   ├── anthropic_provider.py
│   │   ├── gemini_provider.py
│   │   └── ollama_provider.py
│   ├── tests/
│   │   ├── prompt_injection.py
│   │   ├── data_leakage.py
│   │   ├── jailbreak.py
│   │   ├── system_prompt_extraction.py
│   │   ├── indirect_prompt_injection.py
│   │   ├── model_dos.py
│   │   ├── insecure_output_handling.py
│   │   └── training_data_extraction.py
│   ├── semantic/
│   │   └── analyzer.py
│   ├── scoring/
│   │   └── scorer.py
│   └── reporter/
│       └── report_generator.py
├── payloads/
│   ├── injection_payloads.json
│   ├── jailbreak_payloads.json
│   ├── leakage_payloads.json
│   ├── system_prompt_extraction_payloads.json
│   ├── indirect_prompt_injection_payloads.json
│   ├── model_dos_payloads.json
│   ├── insecure_output_handling_payloads.json
│   ├── training_data_extraction_payloads.json
│   └── custom-templates/
├── sample-report/
├── reports/
├── config.py
└── requirements.txt
...
```
---

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
If both layers agree — confidence goes up. If they disagree — the more severe finding wins.

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
