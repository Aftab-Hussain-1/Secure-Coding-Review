# 🛡️ SecureAudit — Python Security Code Review Tool

A complete static security analyzer for Python applications that detects
OWASP Top 10 vulnerabilities, maps them to CWE IDs, and generates
interactive HTML audit reports with remediation guidance.

---

## 📁 Project Structure

```
secure_audit/
├── audit.py                    # CLI entry point
├── core/
│   └── analyzer.py             # Pattern + AST analysis engine
├── rules/
│   └── vulnerability_rules.py  # Vulnerability rule definitions
├── reports/
│   └── html_reporter.py        # Interactive HTML report generator
└── samples/
    └── vulnerable_app.py       # Intentionally vulnerable Flask app (demo target)
```

---

## 🚀 Quick Start

```bash
# Run the unit tests
python -m unittest discover -s tests

# Scan a single file
python audit.py samples/vulnerable_app.py

# Scan the remediated version (should be low risk)
python audit.py samples/remediated_app.py --output reports/remediated_report.html

# Scan with custom report output
python audit.py samples/vulnerable_app.py --output my_report.html

# Filter by severity
python audit.py samples/vulnerable_app.py --severity HIGH

# Scan an entire directory
python audit.py /path/to/your/project/
```

---

## 📄 Deliverables

- Findings report: [SECURITY_REVIEW.md](file:///e:/Cyber%20Task/Secure%20Coding%20Review/SECURITY_REVIEW.md)
- Demo targets:
  - [vulnerable_app.py](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py)
  - [secure_app.py](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/secure_app.py)

## 🔍 Vulnerability Coverage

| Rule ID   | Vulnerability                    | Severity | CWE      | OWASP                        |
|-----------|----------------------------------|----------|----------|------------------------------|
| INJ-001   | SQL Injection                    | CRITICAL | CWE-89   | A03:2021 – Injection         |
| INJ-002   | Command Injection                | CRITICAL | CWE-78   | A03:2021 – Injection         |
| INJ-003   | Code Injection (eval/exec)       | CRITICAL | CWE-95   | A03:2021 – Injection         |
| DESER-001 | Insecure Deserialization (pickle)| CRITICAL | CWE-502  | A08:2021 – Data Integrity    |
| AUTH-001  | Hardcoded Credentials/Secrets    | HIGH     | CWE-798  | A07:2021 – Auth Failures     |
| AUTH-002  | Weak Password Hashing (MD5/SHA1) | HIGH     | CWE-916  | A02:2021 – Crypto Failures   |
| AUTH-003  | Insecure Random Generation       | MEDIUM   | CWE-338  | A02:2021 – Crypto Failures   |
| XSS-001   | Cross-Site Scripting             | HIGH     | CWE-79   | A03:2021 – Injection         |
| PATH-001  | Path Traversal                   | HIGH     | CWE-22   | A01:2021 – Broken Access     |
| CONF-001  | Debug Mode Enabled               | MEDIUM   | CWE-489  | A05:2021 – Misconfiguration  |
| CONF-002  | Open Redirect                    | MEDIUM   | CWE-601  | A01:2021 – Broken Access     |
| INFO-001  | Sensitive Info Disclosure        | MEDIUM   | CWE-200  | A02:2021 – Crypto Failures   |

---

## 📊 Sample Scan Results (vulnerable_app.py)

```
Files scanned:   1
Lines scanned:   141
Total findings:  18

CRITICAL    ██████  6
HIGH        ███████ 7
MEDIUM      █████   5

Risk Score:  100/100
Grade:       F
```

---

## 🏗️ Architecture

### Analysis Engine (`core/analyzer.py`)
- **PatternAnalyzer** — Regex-based line-by-line scanning with confidence scoring
- **ASTAnalyzer** — Abstract Syntax Tree traversal for structural code analysis
- **SecurityAnalyzer** — Orchestrator combining both methods, deduplicates findings

### Rules Engine (`rules/vulnerability_rules.py`)
Each rule contains:
- Regex patterns for pattern matching
- AST check specifications
- CWE ID and OWASP category mapping
- Detailed remediation steps
- Bad/good code examples
- Reference links

### Report Generator (`reports/html_reporter.py`)
Produces a self-contained HTML file with:
- Security grade (A–F) and risk score
- Interactive severity/category charts (Chart.js)
- Expandable finding detail panels
- Severity filter buttons
- Code comparison (bad vs. good)
- Step-by-step remediation guidance
- Clickable reference links

---

## 🛠️ Remediation Quick Reference

### 🔴 CRITICAL — Fix Immediately

**SQL Injection**
```python
# ❌ VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE id='{user_id}'")

# ✅ SECURE
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
```

**Command Injection**
```python
# ❌ VULNERABLE
subprocess.check_output(f"ping {host}", shell=True)

# ✅ SECURE
subprocess.check_output(["ping", "-c", "1", host])
```

**Code Injection**
```python
# ❌ VULNERABLE
result = eval(request.args.get("expr"))

# ✅ SECURE
result = ast.literal_eval(request.args.get("expr"))
```

**Insecure Deserialization**
```python
# ❌ VULNERABLE
data = pickle.loads(request.data)

# ✅ SECURE
data = json.loads(request.get_data(as_text=True))
```

### 🟠 HIGH — Fix This Sprint

**Hardcoded Secrets**
```python
# ❌ VULNERABLE
API_KEY = "sk-1234567890abcdef"

# ✅ SECURE
API_KEY = os.environ.get("API_KEY")
```

**Weak Hashing**
```python
# ❌ VULNERABLE
hashlib.md5(password.encode()).hexdigest()

# ✅ SECURE
argon2.PasswordHasher().hash(password)
```

### 🟡 MEDIUM — Fix This Month

**Insecure Random**
```python
# ❌ VULNERABLE
token = str(random.randint(100000, 999999))

# ✅ SECURE
token = secrets.token_urlsafe(32)
```

**Debug Mode**
```python
# ❌ VULNERABLE
app.run(debug=True, host="0.0.0.0")

# ✅ SECURE
app.run(debug=os.environ.get("FLASK_DEBUG", "False") == "True")
```

---

## 📚 References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Python Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)

---

## ⚠️ Disclaimer

SecureAudit performs static analysis only. Findings require manual
verification. The tool may produce false positives. It does not replace
a full security audit or penetration test.
