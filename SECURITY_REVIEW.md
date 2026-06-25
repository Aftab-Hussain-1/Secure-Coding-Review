# Secure Coding Review (Python)

## Scope

- Language: Python
- Application audited: [vulnerable_app.py](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py)
- Threat model baseline: public-facing web app receiving untrusted input over HTTP

## Methodology

- Manual inspection of request handling and data flows (sources: request.args/request.form/request.data → sinks: SQL, shell, templating, filesystem, deserialization, redirects, code execution).
- Static analysis using the included SecureAudit scanner:

```bash
python audit.py samples/vulnerable_app.py --output reports/security_report.html
```

- Optional third-party tooling:

```bash
pip install -r requirements-dev.txt
bandit -r samples -f txt
pip-audit
```

## High-Level Results

- Overall risk: Very High (multiple RCE vectors, injection, and secret exposure).
- Primary root causes:
  - Untrusted input is used directly in dangerous sinks (SQL, OS commands, eval, pickle).
  - Secrets are hardcoded in source.
  - Missing security controls (authn/authz, CSRF protection, safe redirects, error handling).

## After Remediation (Low-Risk Target)

- Remediated sample: [remediated_app.py](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/remediated_app.py)
- Verified scan output:
  - Findings: 0
  - Risk score: 0/100
  - Grade: A
- Generated report: [remediated_report.html](file:///e:/Cyber%20Task/Secure%20Coding%20Review/reports/remediated_report.html)

## Findings (with Remediation)

### INJ-001 — SQL Injection (CWE-89) — CRITICAL

- Location: [vulnerable_app.py:L26-L36](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L26-L36)
- Issue: User-controlled username/password are interpolated into SQL (line 31).
- Impact: Authentication bypass, data exfiltration, database modification.
- Remediation:
  - Use parameterized queries everywhere.
  - Store password hashes, never plaintext passwords.
  - Use least-privileged DB accounts.
- Safer example: [secure_app.py:login](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/secure_app.py#L35-L56)

### INJ-002 — Command Injection (CWE-78) — CRITICAL

- Location: [vulnerable_app.py:L46-L50](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L46-L50)
- Issue: Untrusted host is passed to a shell command via shell=True (line 49).
- Impact: Remote command execution on the server.
- Remediation:
  - Avoid shell=True, pass arguments as a list.
  - Apply strict allowlisting/validation for host inputs.
  - Prefer library calls over shelling out.
- Safer example: [secure_app.py:ping](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/secure_app.py#L72-L88)

### INJ-003 — Code Injection via eval() (CWE-95) — CRITICAL

- Location: [vulnerable_app.py:L104-L111](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L104-L111)
- Issue: eval() executes attacker-controlled input (line 108).
- Impact: Remote code execution, credential theft, data destruction.
- Remediation:
  - Remove eval/exec for user input.
  - If expression support is required, implement a safe parser with an allowlist of operations.

### DESER-001 — Insecure Deserialization (pickle) (CWE-502) — CRITICAL

- Location: [vulnerable_app.py:L53-L57](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L53-L57)
- Issue: pickle.loads() on untrusted request body (line 56).
- Impact: Remote code execution during deserialization.
- Remediation:
  - Use JSON for interchange.
  - If binary formats are needed, use a schema-driven safe format (e.g., protobuf).
- Safer example: [secure_app.py:load_session](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/secure_app.py#L90-L96)

### AUTH-001 — Hardcoded Secrets (CWE-798) — HIGH

- Locations:
  - [vulnerable_app.py:L18-L23](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L18-L23)
- Issue: Secret key and credentials are embedded in code.
- Impact: Account takeover, session forgery, credential reuse across environments.
- Remediation:
  - Load secrets from environment variables or a secrets manager.
  - Rotate leaked secrets immediately.
- Safer example: [secure_app.py:L15-L17](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/secure_app.py#L15-L17)

### AUTH-002 — Weak Password Hashing (MD5) (CWE-916) — HIGH

- Location: [vulnerable_app.py:L67-L69](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L67-L69)
- Issue: MD5 is used for password hashing (line 68).
- Impact: Offline cracking at scale.
- Remediation:
  - Use a dedicated password hashing algorithm (Argon2id/bcrypt/PBKDF2) with proper parameters.
  - Enforce password policy + MFA where possible.
- Safer example: [secure_app.py:register](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/secure_app.py#L59-L70)

### AUTH-003 — Insecure Random (CWE-338) — MEDIUM

- Location: [vulnerable_app.py:L71-L76](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L71-L76)
- Issue: random.randint() is used for token generation (line 75).
- Impact: Predictable tokens → session/account compromise.
- Remediation:
  - Use secrets.token_urlsafe()/token_hex() for security tokens.

### XSS-001 — Cross-Site Scripting (CWE-79) — HIGH

- Location: [vulnerable_app.py:L39-L43](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L39-L43)
- Issue: User input is rendered directly in HTML via render_template_string and f-string (line 42).
- Impact: Session theft, phishing, CSRF amplification.
- Remediation:
  - Escape output by default; avoid rendering raw user input into templates.
  - Add Content-Security-Policy (CSP) headers.
- Safer example: [secure_app.py:search](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/secure_app.py#L72-L74)

### PATH-001 — Path Traversal (CWE-22) — HIGH

- Location: [vulnerable_app.py:L60-L65](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L60-L65)
- Issue: Filename from request is concatenated into a filesystem path (line 63).
- Impact: Reading arbitrary files, secret disclosure, lateral movement.
- Remediation:
  - Use an allowlisted base directory and verify resolved paths remain inside it.
  - Use a safe filename policy.
- Safer example: [secure_app.py:read_file](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/secure_app.py#L98-L110)

### CONF-001 — Debug Mode Enabled (CWE-489) — MEDIUM

- Location: [vulnerable_app.py:L114-L115](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L114-L115)
- Issue: debug=True and binding to all interfaces.
- Impact: Debug console exposure, sensitive information leakage.
- Remediation:
  - Disable debug in production.
  - Bind to localhost by default; use a real WSGI server in production.
- Safer example: [secure_app.py:L150-L152](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/secure_app.py#L150-L152)

### CONF-002 — Open Redirect (CWE-601) — MEDIUM

- Location: [vulnerable_app.py:L98-L102](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L98-L102)
- Issue: Redirect target is fully user-controlled (line 101).
- Impact: Phishing, token leakage via crafted links.
- Remediation:
  - Only allow relative redirects or an allowlist of known hosts.
- Safer example: [secure_app.py:redirect_user](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/secure_app.py#L141-L147)

### INFO-001 — Sensitive Information Disclosure (CWE-200) — MEDIUM

- Location: [vulnerable_app.py:L78-L82](file:///e:/Cyber%20Task/Secure%20Coding%20Review/samples/vulnerable_app.py#L78-L82)
- Issue: Environment variables are returned to the client (line 80).
- Impact: Secret leakage, easier exploitation.
- Remediation:
  - Never return env/config details to clients.
  - Log server-side and return generic errors.

## Secure Coding Recommendations (General)

- Input handling: validate at boundaries, and encode/escape at sinks (SQL, HTML, OS, filesystem, redirects).
- Secrets: keep secrets out of code; use environment/secrets manager; rotate on exposure.
- Authn/Authz: enforce authentication for sensitive actions; implement authorization checks per resource.
- Crypto: use battle-tested primitives (secrets, TLS, password hashing); never build custom crypto.
- Error handling: don’t leak stack traces or configuration; log securely with structured logs.
- Production hardening: disable debug, set security headers (CSP, HSTS where applicable), run behind a WSGI server, and apply least privilege.
