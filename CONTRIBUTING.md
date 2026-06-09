# Contributing to AI Model Security Scanner

Thanks for your interest in contributing! This tool is built by and for security researchers.

---

## 🧪 Adding a New Test Module

1. Create a new file in `scanner/tests/your_test_name.py`
2. Follow this structure:

```python
def run_test(provider, api_url, api_key, model, verbose=False, custom_payloads=None):
    print("[*] Running Your Test Name Tests...")
    results = []
    # load payloads, call provider.call(), detect, return results
    return results

def detect_your_test(response):
    # return {"vulnerable": bool, "severity": str, "confidence": int, "reason": str}
```

3. Add your payload file to `payloads/your_test_name_payloads.json`:
```json
{
  "payloads": [
    "Your payload 1",
    "Your payload 2"
  ]
}
```

4. Register your test in `scanner/main.py` in the `ALL_TESTS` list
5. Add OWASP mapping in `scanner/scoring/scorer.py` in `OWASP_MAPPING`

---

## 📦 Adding Custom Payloads

Copy a template from `payloads/custom-templates/` and fill in your payloads.
The filename must contain the test key for auto-detection.

---

## 🐛 Reporting Issues

Open a GitHub issue with:
- What you were testing
- What you expected vs what happened
- Any error messages

---

## 📋 Guidelines

- Only submit payloads for authorized testing
- Do not include real API keys or credentials
- Test your changes before submitting a PR
- Follow the existing code style

---

## 👤 Author

Maryssa L. — [@Gemz-AACT](https://github.com/Gemz-AACT)
