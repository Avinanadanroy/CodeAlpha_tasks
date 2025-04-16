# 🛡️ Secure Code Review : Cross-Site Scripting (XSS)

This task demonstrates how a web application can be vulnerable to Cross-Site Scripting (XSS), and how to fix it using proper input sanitization and output escaping.

---
## 📚 Overview: What is XSS?

**Cross-Site Scripting (XSS)** is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. These scripts can steal session cookies, log keystrokes, or hijack user sessions.

There are 3 major types of XSS:
- **Reflected XSS** – malicious script is reflected off the server in an immediate response.
- **Stored XSS** – script is permanently stored (e.g. in a comment).
- **DOM-based XSS** – script is injected via client-side scripts.

---

## ⚙️ prerequisites

- Python 3.x
- Flask
- Markupsafe
Install Flask:

Bash
 `pip install Flask`

 `pip install markupsafe`

---

## Run the XSS vulnerable code
    `python xss.py`

---

## Run the XSS payloads

1. http://127.0.0.1:5000/?name=<script>alert('XSS')</script>

2. http://127.0.0.1:5000/?name=";alert('XSS');// 

---

## Run the XSS fixed code and the payloads

    `python xss_fixed.py`
    
1. http://127.0.0.1:5000/?name=<script>alert('XSS')</script>

2. http://127.0.0.1:5000/?name=";alert('XSS');//

---

### Outputs

- Payload 1 output
![Image](https://github.com/user-attachments/assets/6d93f7d0-e065-467f-98f9-ed1d62e3a5ab)

- Payload 2 output
![Image](https://github.com/user-attachments/assets/60d56e75-a589-4439-8308-0d928c5704cf)

- XSS Fixed output
![Image](https://github.com/user-attachments/assets/366fd875-370d-40e5-bc20-c5832ce7c53e)
