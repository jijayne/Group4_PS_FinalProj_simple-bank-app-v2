# Secure Flask Banking Application

## 👥 Group Members
- [Jane Cagorong]
- [Justine Son Camila]
- [Mark Angelo Umacam]


## 📘 Introduction

This project is a secure online banking system built with Flask. It includes features for users, administrators, and managers to manage accounts, perform transfers, and track transactions. The original application was assessed for vulnerabilities and has been enhanced based on penetration testing results to improve overall security.

## 🎯 Objectives

- Identify and assess security vulnerabilities in the original banking application.
- Implement security best practices to harden the application.
- Perform penetration testing to validate security improvements.
- Deploy a secure version of the application online.

## ✨ Original Application Features

- User registration and login
- Role-based dashboards (User, Admin, Manager)
- Account management and transfers
- Admin creation and deposit functionalities
- Manager control over users and admins
- Reset password mechanism

## 🚨 Security Assessment Findings

During the initial assessment, the following vulnerabilities were discovered:

- **Lack of CSRF Protection** on sensitive forms.
- **No rate limiting** on login and sensitive routes.
- **Missing content security policies**, leaving the app open to XSS.
- **Improper session configurations**, risking session hijacking.
- **No input validation/sanitization**, allowing possible injection attacks.
- **Weak password storage mechanism** or missing hashing in earlier versions.

## 🔐 Security Improvements Implemented

To address the above findings, we made the following changes:

- ✅ Implemented **CSRF protection** via `Flask-WTF`.
- ✅ Enforced **HTTP security headers** using `Flask-Talisman`.
- ✅ Configured **secure session cookies** (`SESSION_COOKIE_SECURE`, `HTTPONLY`).
- ✅ Added **rate limiting** using `Flask-Limiter`.
- ✅ Enforced **strong password hashing** using `bcrypt`.
- ✅ Added **input sanitization and form validation**.
- ✅ Utilized `itsdangerous` for secure reset token generation.

## 🧪 Penetration Testing Report

### Identified Vulnerabilities:
- CSRF on transaction and login forms
- Login brute-force vulnerability
- XSS risk in input fields
- Insecure password reset token handling

### Exploitation Steps:
1. Replayed POST request to `/transfer` without CSRF token.
2. Performed brute-force attack on `/login` without any lockout.
3. Injected scripts into unescaped fields in templates.
4. Accessed reset password endpoint with manipulated tokens.

### Recommendations:
- Enforce CSRF tokens on all POST requests
- Implement rate limiting and brute-force protection
- Escape user input in all templates
- Use time-limited, signed tokens for password reset

## 🛠 Remediation Plan

- Integrated CSRF middleware and tokens for all sensitive forms
- Configured `Flask-Limiter` with thresholds on login and reset
- Used Jinja2 auto-escaping and manually escaped where necessary
- Used `URLSafeTimedSerializer` for secure, time-limited reset tokens
- Enforced HTTPS-only cookies and session security best practices

## 🧰 Technology Stack

| Component       | Technology          |
|----------------|---------------------|
| Backend         | Flask               |
| Frontend        | Jinja2, HTML/CSS    |
| Database        | SQLite              |
| Extensions      | Flask-WTF, Flask-Login, Flask-Bcrypt, Flask-Limiter, Flask-Talisman |
| Deployment      | PythonAnywhere      |
| Language        | Python              |

## 🚀 Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/your-username/secure-flask-banking-app.git
cd secure-flask-banking-app
```

### 2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows use venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set environment variables
Create a `.env` file in the project root:

```
SECRET_KEY=your_secure_secret_key
```

### 5. Run the app locally
```bash
python app.py
```

Visit: `http://127.0.0.1:5000`


## 🌐 Live Web Application

Access the deployed secure banking system here:  
➡️ 
