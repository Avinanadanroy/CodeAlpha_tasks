# 🛡️ Command Injection Secure Code Review

This task demonstrates the Command Injection vulnerability through a simple Flask web application and provides a secure version as a mitigation example.

---

### Description

The vulnerable app allows users to input a hostname to "ping". However, the input is directly injected into a system command without validation, allowing attackers to inject additional commands.

---

### Prerequisites

Before running the Command Injection application, ensure you have the following installed:

- **Python**: Version 3.6 or higher is recommended. You can download it from [python.org](https://www.python.org/downloads/).
- **Flask**: A micro web framework for Python. You can install it using pip:

```bash
pip install Flask

---

### Key Vulnerability

```python
command = "ping -n 1 " + host
os.popen(command).read()

-->> No input sanitization

-->> Uses os.popen() which executes system commands

-->> Combines user input directly into shell commands

---

### Run the Vulnerable command injection script
 Bash
  >> python command_injection.py

---
### Run vulnerable payloads
1. http://127.0.0.1:5000/ping?host=127.0.0.1%20%26%20whoami
2. http://127.0.0.1:5000/ping?host=127.0.0.1%20%26%20echo%20hacked
3. http://127.0.0.1:5000/ping?host=127.0.0.1%20%26%20dir
4. http://127.0.0.1:5000/ping?host=127.0.0.1%20%26%20whoami%20%26%20hostname


### Run the Secure command injection script
 Bash
 >> python command_injection_fix.py

 Run the secure payloads again.