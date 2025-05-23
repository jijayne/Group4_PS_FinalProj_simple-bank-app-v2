# Group4_PS_FinalProj

🧪 Tool: pip-audit
🔍 Purpose: To detect known security issues in third-party Python packages
📊 Findings:
- [example] Flask 2.0.1 has known vulnerabilities (CVE-XXXX-XXXX)
- [example] SQLAlchemy 1.3.0 is outdated — recommend updating to 1.4.0 or later

✅ Remediation Plan:
- Run `pip install --upgrade [package-name]` to fix
- Updated Flask and SQLAlchemy to secure versions


🧪 Tool: Burp Suite Community Edition
🔍 Purpose: Intercept and analyze HTTP requests and responses
📊 Findings:
- No CSRF token detected on transfer form
- Admin page was accessible without proper role
- Input validation for `<script>` not sanitized

✅ Remediation Plan:
- Enforce CSRF protection using Flask-WTF
- Restrict access using Flask-Login decorators
- Sanitize inputs on both client and server sides


[3]
We used Nmap to scan our local system (127.0.0.1) while the Flask banking app was running. The following results were obtained:

Test	Result
Nmap Basic Scan	Open ports found: 135, 445, 3306, 5000, 8080, 8090
Detected Services	- Port 135: Microsoft RPC
- Port 445: Windows SMB
- Port 3306: MySQL 8.0.40
- Port 5000: Werkzeug HTTP Server 3.1.3
- Port 8080: Burp Suite Community Proxy
- Port 8090: Unidentified (tcpwrapped)
Vulnerabilities Detected	✅ Slowloris DoS attack (CVE-2007-6750)
✅ phpMyAdmin Local File Inclusion (CVE-2005-3299) (status: unknown)
✅ Litespeed Source Code Disclosure (CVE-2010-2333)
Risks/Findings	- Port 3306 (MySQL) should not be publicly accessible.
- Flask development server should not be exposed in production.
- Web server may be vulnerable to Slowloris attacks.
- phpMyAdmin and Litespeed-related issues found.
Recommendations	- Use a WSGI server like Gunicorn or uWSGI for deployment.
- Firewall the database port (3306) in production.
- Disable unused ports (like 8090) if not required.
- Investigate and mitigate CVE vulnerabilities found.
Screenshot Proof	
(You need to save and include your screenshot here)



## 🔐 Step 3: Security Gap Analysis and Recommendations

Based on our vulnerability testing using Burp Suite, Nmap, and static code analysis, we identified the following issues in our banking app and made recommendations for each:

| Area                         | Finding / Risk                                                                 | Recommendation                                                                 |
|------------------------------|---------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| 🔒 Secure Data Storage       | Passwords were not using strong hash algorithms.                               | Use **bcrypt** with salting for password storage.                              |
| 🧼 Input Validation          | Some input fields accepted `<script>` and SQL characters.                      | Sanitize and validate all inputs server-side. Use **Flask-WTF** and parameterized queries. |
| 👤 Auth & Authorization      | Users could access `/admin` without role checks.                              | Implement **role-based access control (RBAC)**.                                |
| 🧁 Session Management        | Session cookie not marked `HttpOnly` or `Secure`.                             | Use `session.cookie_httponly = True` and `session.cookie_secure = True`.       |
| 🛡️ CSRF Protection           | Some POST forms were missing CSRF tokens.                                     | Add CSRF protection using **Flask-WTF**.                                       |
| ❌ Error Handling            | Error messages revealed stack traces and app info.                            | Show generic error pages and log details in the backend only.                  |
| 💻 Output Encoding           | User inputs were rendered unescaped in HTML.                                  | Use Jinja’s autoescaping or manually escape user data in templates.            |
| 📦 Dependency Management     | `Werkzeug` is in development mode; outdated MySQL version detected.           | Update packages using `pip-audit` or `pip list --outdated`.                    |
| 🔄 Rate Limiting             | No brute-force protection on login detected.                                  | Use `Flask-Limiter` to rate-limit login attempts.                              |
| 🔐 Secure Communication      | The app runs over HTTP (port 5000), not HTTPS.                                | Use **SSL/TLS** via reverse proxy (e.g., Nginx or Gunicorn + HTTPS cert).      |


## ✅ Step 4: Security Fixes Done

- [x] CSRF protection added with Flask-WTF
- [x] Session cookies made secure and HttpOnly
- [x] Security headers added using Flask-Talisman
- [x] Password reset tokens expire after 30 minutes
- [x] Regenerate session ID after login
- [x] Added logging for failed login attempts
- [x] All forms now include CSRF tokens
- [x] Manual regression testing completed
