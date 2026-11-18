# CodeAlpha_SecureCodeReview

A security code review of [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App), a Python/Flask application built for security testing. Done for CodeAlpha Cyber Security Internship, Task 3.

The full write-up is in **[REPORT.md](REPORT.md)**.

## Result

12 findings: 4 critical, 5 high, 1 medium, 2 low.

| Severity | Findings |
|---|---|
| Critical | Template injection in error pages, SQL injection, unsafe YAML loading, JWT signature check disabled |
| High | Any user can read any customer's card number, hardcoded secrets and default admin login, plaintext passwords and MD5, unrestricted file upload, 153 known vulnerabilities in 14 dependencies |
| Medium | Passwords and personal data written to logs |
| Low | Verbose errors, no brute-force protection |

Each finding has the vulnerable lines, the impact, a CWE and OWASP Top 10 reference, and a fix.

## Method

1. Static analysis with Bandit
2. Dependency audit with pip-audit
3. Manual review of every route, the authentication code, file handling and error handling

Bandit found 5 of the 12 issues and pip-audit found 1. The other 6, including two critical ones, were found only by reading the code. The report explains why.

## Proof that the fixes work

`fixes/patterns.py` has a vulnerable and a fixed version of five patterns: SQL query, YAML loading, error page, JWT check and password storage. The tests use harmless inputs to show the vulnerable version can be abused and the fixed one cannot.

```bash
pip install -r requirements.txt
python3 -m unittest discover -t . -s tests
```

## Reproduce the scans

```bash
./scripts/run_scan.sh
```

Raw tool output is saved in `evidence/`.

## Layout

```
REPORT.md          findings, impact and remediation
fixes/patterns.py  vulnerable and fixed versions of five patterns
tests/             15 tests for those patterns
evidence/          Bandit and pip-audit output
scripts/           script to repeat the scans
```

## Note

The reviewed application is intentionally vulnerable and was not run against any live system. Do not use these techniques on systems you do not own or have permission to test.
