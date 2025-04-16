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

bash
`pip install Flask`

---

### Key Vulnerability

python
command = "ping -n 1 " + host
os.popen(command).read()

-->> No input sanitization

-->> Uses os.popen() which executes system commands

-->> Combines user input directly into shell commands

---

### Run the Vulnerable command injection script
 Bash
   `python command_injection.py`

---
### Run vulnerable payloads
1. http://127.0.0.1:5000/ping?host=127.0.0.1%20%26%20whoami
2. http://127.0.0.1:5000/ping?host=127.0.0.1%20%26%20echo%20hacked
3. http://127.0.0.1:5000/ping?host=127.0.0.1%20%26%20dir
4. http://127.0.0.1:5000/ping?host=127.0.0.1%20%26%20whoami%20%26%20hostname

---

### Run the Secure command injection script
 Bash
   `python command_injection_fix.py`

 Run the payloads again.

 ---

 ### Outputs

 - Payload 1 output
![Image](https://github.com/user-attachments/assets/ac693c1b-d48d-4128-bbda-c1bc395f2403)

- Payload 2 output
![Image](https://github.com/user-attachments/assets/2c042bab-4c22-41e4-9b4a-0ef9adba87a2)

- Payload 3 output
![Image](https://github.com/user-attachments/assets/999de5de-087f-4dcb-80dd-eceaaed19ef5)

- Payload 4 output
![Image](https://github.com/user-attachments/assets/8efd4384-1954-4c5c-9e6f-e537f4caa939)

- Command injection fix output
![Image](https://github.com/user-attachments/assets/bff18f90-535d-4285-9ffe-6bb7e8b5d372)
