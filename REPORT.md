# Secure Coding Review: Vulnerable-Flask-App

CodeAlpha Cyber Security Internship, Task 3.
Reviewer: Zayan (Zeon-Tech-Sec)

## 1. Scope and method

| Item | Detail |
|---|---|
| Application | [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App), commit `b6a4f97` |
| Language | Python 3, Flask, SQLAlchemy, PyJWT, Tornado |
| Code reviewed | `app/app.py` (339 lines, 282 lines of code), `app/requirements.txt`, templates |
| Static analysis | Bandit 1.9.4 |
| Dependency analysis | pip-audit against the pinned versions in `requirements.txt` |
| Manual review | Line-by-line read of all routes, auth, data handling, file handling and error handling |
| Not done | Dynamic testing. The app was not run, so findings that depend on runtime behaviour are marked "needs confirmation" |

The target is an intentionally vulnerable training application published for security testing. Nothing in this review was run against a live system. Line numbers refer to the commit above.

Severity reflects how easy the flaw is to reach and how much damage it can do. CWE and OWASP Top 10 (2021) references are given for each finding.

## 2. Summary

12 findings: 4 critical, 5 high, 1 medium, 2 low.

| ID | Severity | Finding | CWE | OWASP 2021 | Lines | Found by |
|---|---|---|---|---|---|---|
| F1 | Critical | Template injection in error pages | CWE-1336 | A03 Injection | 101-114, 270-281 | Manual |
| F2 | Critical | SQL injection in `/search` | CWE-89 | A03 Injection | 261-265 | Bandit + manual |
| F3 | Critical | Unsafe YAML deserialisation | CWE-502 | A08 Integrity Failures | 329 | Bandit + manual |
| F4 | Critical | JWT signature check disabled | CWE-347 | A07 Authentication Failures | 96-99, 227 | Manual |
| F5 | High | Any logged-in user can read any customer, including card numbers | CWE-639, CWE-200 | A01 Broken Access Control | 196-241 | Manual |
| F6 | High | Hardcoded secrets and default admin login | CWE-798, CWE-259 | A07 Authentication Failures | 26-28, 62-63 | Bandit + manual |
| F7 | High | Plaintext passwords and weak MD5 | CWE-522, CWE-327, CWE-916 | A02 Cryptographic Failures | 49, 141, 182 | Bandit + manual |
| F8 | High | Unrestricted file upload and unsafe parsing | CWE-434, CWE-611 | A04, A05 | 290-308, 315-331 | Manual (Bandit: weak random) |
| F9 | Medium | Secrets and personal data written to logs | CWE-532 | A09 Logging Failures | 87, 98, 179, 260, 268 | Manual |
| F10 | Low | Verbose errors, bare `except`, crash on GET | CWE-209, CWE-755 | A05 Misconfiguration | 148, 167, 193, 308 | Manual |
| F11 | Low | No brute-force protection, long-lived tokens | CWE-307 | A07 Authentication Failures | 80-82, 170-194 | Manual |
| F12 | High | Outdated components: 153 known vulnerabilities | CWE-1104 | A06 Vulnerable Components | `requirements.txt` | pip-audit |

### Tools against manual review

Bandit reported 9 issues (1 high, 2 medium, 6 low). They map to F2, F3, F6, F7 and part of F8. pip-audit produced F12. The other six findings (F1, F4, F5, F9, F10, F11) were found only by reading the code, and two of them (F1, F4) are critical. The worst example is F4: the function simply returns `True` for any token, which no scanner flags because the code is syntactically fine.

Bandit also rated the hardcoded secrets as low. They are high here, because the JWT signing key is the word `secret` and anyone who guesses it can forge a login for any user.

## 3. Findings

### F1. Template injection in error pages (Critical)

**Where:** `pnf()` at lines 101-114 and the error branch of `search_customer()` at lines 270-281.

**What:** The code builds a template string by inserting `request.url` (and later `str(e)`) into it, then passes the whole string to `render_template_string`. Whatever the user puts in the URL becomes part of the template source, so the template engine runs it.

```python
template = '''<html>... <h3>%s</h3> ...</html>''' % request.url
return render_template_string(template, dir=dir, help=help, locals=locals), 404
```

Passing `dir`, `help` and `locals` into the template also hands the attacker Python built-ins to work with.

**Impact:** At minimum reflected cross-site scripting. In Jinja2 this class of bug typically allows reading server configuration (including the secret keys in F6) and running code on the server.

**Fix:** Keep user input out of the template source. Pass it as a variable so it is escaped.

```python
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", url=request.url), 404
```

`404.html` contains `<h3>{{ url }}</h3>`. For the search error branch, return a generic JSON error and log the details on the server (see F10).

**Verified:** `tests/test_patterns.py::TemplateInjection` shows `{{ 7 * 7 }}` is evaluated by the vulnerable pattern and printed as text by the fixed one.

### F2. SQL injection in `/search` (Critical)

**Where:** Line 261, executed at line 265.

```python
str_query = "SELECT first_name, last_name, username FROM customer WHERE username = '%s';" % search_term
search_query = db.engine.execute(str_query)
```

**What:** The search term is pasted into the SQL text. A value such as `x' OR '1'='1` changes the meaning of the query and returns every row. The ORM version that would have been safe is commented out two lines above.

**Impact:** Read access to the whole database, including the customer table with card numbers and passwords. Depending on the database, possible data modification.

**Fix:** Use the ORM or bound parameters.

```python
rows = (Customer.query
        .with_entities(Customer.first_name, Customer.last_name, Customer.username)
        .filter_by(username=search_term).all())
```

**Verified:** `tests/test_patterns.py::SqlInjection`. The vulnerable query returns all 3 rows for the payload, the parameterised one returns none and still finds real users.

### F3. Unsafe YAML deserialisation (Critical)

**Where:** Line 329, `ydata = yaml.load(y)` on an uploaded file. `requirements.txt` pins PyYAML 3.12.

**What:** In PyYAML 3.12, `yaml.load` without a safe loader can build arbitrary Python objects from tags in the file. An uploaded file can therefore make the server call functions of the attacker's choosing.

**Impact:** Remote code execution through the `/yaml_hammer` upload.

**Fix:** Use `yaml.safe_load`, check the file size and extension, and validate the parsed structure against the shape you expect.

```python
ydata = yaml.safe_load(y)
```

**Verified:** `tests/test_patterns.py::YamlDeserialisation` uses a harmless function (`os.getcwd`) to show the unsafe loader executes it, while `safe_load` raises an error.

### F4. JWT signature check disabled (Critical)

**Where:** `insecure_verify()` at lines 96-99, used by `/get/<cust_id>` at line 227.

```python
def insecure_verify(token):
    decoded = jwt.decode(token, verify=False)
    print(decoded)
    return True
```

**What:** The token is decoded without checking its signature, and the function always returns `True`. Anyone can create a token with any content and the endpoint accepts it.

**Impact:** Authentication bypass on `/get/<cust_id>`, which returns customer records (see F5).

**Fix:** Delete `insecure_verify`. Use one verification path for every protected route, as a decorator.

```python
def require_jwt(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "")
        try:
            claims = jwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"], issuer="we45")
        except jwt.InvalidTokenError:
            return jsonify({"Error": "Invalid token"}), 401
        g.user = claims["user"]
        return view(*args, **kwargs)
    return wrapper
```

`verify_jwt()` (lines 84-94) is closer to correct because it fixes the algorithm and checks the issuer, but it only catches two exception types, so an expired token raises an unhandled error.

**Verified:** `tests/test_patterns.py::JwtVerification`. The vulnerable check accepts a token signed with any key. The fixed check rejects a wrong signature and an unsigned token, and accepts a genuine one.

### F5. Broken access control and excessive data exposure (High)

**Where:** `/fetch/customer` (lines 196-218) and `/get/<cust_id>` (lines 221-241).

**What:** After the token check, the code returns whichever customer ID was requested. There is no check that the caller is allowed to see that record, and the response includes the full credit card number. IDs are small sequential integers, so every record can be walked through.

There is also a logic bug at lines 209-213: the response dictionary is built before the code checks whether the record exists, so an unknown ID raises an error instead of returning "not found".

**Impact:** Any authenticated user (or anyone, because of F4) can download every customer's name, email and card number.

**Fix:**
1. Add an owner or role check before returning a record, and return 403 if it fails.
2. Return only the fields the caller needs. Mask card numbers (`**** **** **** 1234`).
3. Do not store full card numbers at all. Use a payment provider's token, which also keeps the system out of most card-data compliance scope.
4. Check for `None` before building the response.

```python
customer = db.session.get(Customer, customer_id)
if customer is None:
    return jsonify({"Error": "No customer found"}), 404
if customer.owner != g.user and not g.is_admin:
    return jsonify({"Error": "Forbidden"}), 403
return jsonify({"id": customer.id, "name": customer.first_name, "card": "****" + customer.ccn[-4:]})
```

### F6. Hardcoded secrets and default admin login (High)

**Where:** Lines 26-28 and 62-63.

```python
app.config['SECRET_KEY_HMAC'] = 'secret'
app.config['SECRET_KEY_HMAC_2'] = 'am0r3C0mpl3xK3y'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'
...
user.username = 'admin'
user.password = 'admin123'
```

**What:** The JWT signing key is the word `secret`, and the session key and a second key sit in the source code. A default `admin` account is created on first start with a guessable password.

**Impact:** Anyone with the code or a dictionary can forge tokens and sessions. Anyone can try `admin` / `admin123`.

**Fix:**
- Load secrets from environment variables or a secrets manager and refuse to start if they are missing.
- Generate keys with `python -c "import secrets; print(secrets.token_hex(32))"`.
- Remove the default account. Create the first admin through a one-time setup command that asks for a password.
- Rotate every key that has been committed, since they stay in the Git history.

```python
app.config["JWT_SECRET"] = os.environ["JWT_SECRET"]
app.secret_key = os.environ["SECRET_KEY"]
```

### F7. Plaintext passwords and weak hashing (High)

**Where:** Lines 49 and 161 (customer passwords stored as given), line 141 (MD5), line 182 (login compares plaintext).

**What:** Customer passwords are saved as received. User registration hashes with MD5, which is fast and unsalted and can be cracked in bulk. The login route compares the submitted password directly with the stored value, which only works if the password was stored in plaintext. The code for registration is also broken (`md5()` needs bytes, `e.message` is Python 2 only, and the `User` constructor does not match the model), so the two paths are inconsistent.

**Impact:** A database leak exposes every password, and users who reuse passwords are exposed elsewhere.

**Fix:** Hash with a slow, salted algorithm and compare with the library function.

```python
from werkzeug.security import generate_password_hash, check_password_hash

user.password = generate_password_hash(password)
...
user = User.query.filter_by(username=username).first()
if user and check_password_hash(user.password, password):
    ...
```

**Verified:** `tests/test_patterns.py::PasswordStorage` checks that hashes do not contain the password, differ between calls (salted), and verify correctly.

### F8. Unrestricted file upload and unsafe parsing (High)

**Where:** `/xxe_uploader` (lines 290-308) and `/yaml_hammer` (lines 315-331).

**What:**
- Any file type and size is accepted and saved before it is checked. `secure_filename` is used, which is good, but the only uniqueness is a random number from 1 to 100 (lines 295, 319, flagged by Bandit as weak randomness), so uploads overwrite each other.
- The DOCX upload is parsed with python-docx and lxml 4.2.1. Older lxml versions can resolve external entities, so XXE (reading local files through crafted XML) is possible. This needs dynamic testing to confirm and is rated on the safe assumption that it is exploitable.
- On a GET request, `para` is never defined, so line 308 crashes.

**Impact:** Disk filling, file overwrite, possible local file disclosure, and the code execution described in F3.

**Fix:**
- Allow only the extensions you need, set `app.config["MAX_CONTENT_LENGTH"]`, and check the file before saving.
- Name files with `uuid.uuid4().hex` and store them outside the web root.
- Upgrade lxml and python-docx, and parse untrusted XML with a parser that has entity resolution disabled (or with `defusedxml`).
- Initialise variables before use.

### F9. Secrets and personal data in logs (Medium)

**Where:** Lines 87, 98, 179, 260 and 268.

**What:** `print` is used to write the decoded JWT claims, the full login body (which includes the password at line 179), the search term and the search results.

**Impact:** Anyone who can read the logs gets passwords and customer data.

**Fix:** Use the `logging` module, log events (such as "login failed for user X") and never credentials, tokens or card data.

### F10. Verbose errors and weak error handling (Low)

**Where:** Lines 148 and 167 (`str(e.message)` returned to the client), line 193 (bare `except:`), line 308.

**What:** Exceptions are returned to the caller, which leaks internal details. The bare `except` hides real bugs, and error responses use the wrong status code (404 for a failed registration).

**Fix:** Catch specific exceptions, return a generic message with the right status code, and log the detail with an error ID on the server.

### F11. No brute-force protection and long-lived tokens (Low)

**Where:** `login()` (lines 170-194) and `get_exp_date()` (lines 80-82).

**What:** Unlimited login attempts are allowed, and a token lasts 240 minutes with no way to revoke it. Combined with the default account in F6, guessing is easy.

**Fix:** Rate-limit login (for example with Flask-Limiter at 5 per minute per IP and account), add lockout or back-off, shorten token life to about 15 minutes with a refresh token, and offer multi-factor authentication for admin accounts.

### F12. Outdated components (High)

**Where:** `app/requirements.txt`. pip-audit found **153 known vulnerabilities in 14 packages** among the pinned versions.

| Package | Pinned | Known vulns | Upgrade to at least |
|---|---|---|---|
| tornado | 4.5.1 | 36 | 6.6.1 |
| werkzeug | 0.14.1 | 21 | 3.1.9 |
| urllib3 | 1.21.1 | 21 | 2.8.0 |
| pyjwt | 1.5.2 | 15 | 2.14.0 |
| lxml | 4.2.1 | 12 | 6.1.0 |
| jinja2 | 2.9.6 | 12 | 3.1.6 |
| requests | 2.18.1 | 10 | 2.33.0 |
| flask | 0.12.2 | 8 | 3.1.3 |
| sqlalchemy | 1.1.11 | 4 | current 2.x |
| pyyaml | 3.12 | 4 | 5.4 or later |
| idna | 2.5 | 4 | 3.15 |
| python-docx | 0.8.5 | 2 | 0.8.6 |
| gevent | 1.2.2 | 2 | 23.9.0 |
| certifi | 2017.4.17 | 2 | 2023.7.22 |

Full output is in `evidence/pip_audit.json`. The counts reflect the vulnerability database on the day the scan ran and will change over time. Several upgrades are major versions, so the code (for example `jwt.decode(..., verify=...)`, `before_first_request`, `db.engine.execute`) needs updating alongside them.

**Fix:** Upgrade, pin with hashes, and run `pip-audit` in CI so new advisories fail the build.

## 4. Fix priority

1. Within 24 hours: F4 (token check), F2 (SQL injection), F3 (YAML), F1 (template injection), F6 (rotate secrets, remove the default login).
2. Within 30 days: F5 (access control), F7 (password hashing), F8 (uploads), F12 (dependencies).
3. Within 90 days: F9, F10, F11, plus a CI pipeline with Bandit and pip-audit.

## 5. Secure coding checklist from this review

- Never build SQL, HTML or templates by joining strings with user input. Use parameters and autoescaping.
- Use the safe variant of every deserialiser (`yaml.safe_load`).
- Verify signatures on every token, on every route, from one shared function.
- Check authorisation on the server for every object, not only authentication.
- Keep secrets out of source control. Hash passwords with a slow salted algorithm.
- Log events, not secrets. Return generic errors to users.
- Validate uploads before saving them. Limit size and type.
- Keep dependencies current and scan them automatically.
- Use scanners for coverage and humans for logic. Each missed what the other found.

## 6. Limitations

- Static review only: no runtime testing, so F8's XXE needs confirmation.
- Bandit and pip-audit were used. A rules-based scanner such as Semgrep could not download its rule sets in the environment used for this review and would likely add findings.
- The application is a deliberately vulnerable training target, so the number of issues is not typical of real software. The patterns, however, are common ones.

## 7. Proof the fixes work

`fixes/patterns.py` holds a vulnerable and a fixed version of five patterns (SQL query, YAML loading, error page, JWT check, password storage). `tests/test_patterns.py` runs 15 tests showing the vulnerable version is exploitable with harmless inputs and the fixed one is not.

```bash
python3 -m unittest discover -t . -s tests
```
