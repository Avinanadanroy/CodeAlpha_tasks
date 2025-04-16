# 🔐 Path Traversal Secure Code Review

This task demonstrates a classic Path Traversal vulnerability using a Flask web application, and includes both a vulnerable and secure implementation for security testing, awareness, and code review training.

---

## Prerequisites

Before running the Path Traversal application, ensure you have the following installed:

- **Python**: Version 3.6 or higher is recommended. You can download it from [python.org](https://www.python.org/downloads/).
- **Flask**: A micro web framework for Python. You can install it using pip:

bash
`pip install Flask`

---

## 🚨 Vulnerable Version

The vulnerable version (`vulnerable_app.py`) uses direct user input from query parameters to read files on the server, allowing attackers to traverse directories using `../`.

### 🔓 Code Behavior
python
`filepath = os.getcwd() + "/" + filename  # No validation
with open(filepath, 'rb') as f:
    content = f.read()`

---

### Run vulnerable Path traversal python script
    bash
    `python path_traversal.py`

---

### Test Payloads for LINUX
1. http://127.0.0.1:5000/download?filename=../../../../../etc/passwd

2. http://127.0.0.1:5000/download?filename=../../../../../etc/hosts

3. http://127.0.0.1:5000/download?filename=../../../../../var/log/auth.log


### Test Payloads for WINDOWS
1. http://127.0.0.1:5000/download?filename=../../../../../../Windows/system.ini

2. http://127.0.0.1:5000/download?filename=../../../../../../Windows/win.ini

3. http://127.0.0.1:5000/download?filename=../../../../../../Windows/System32/drivers/etc/hosts

---

## 💡 Run Secure Version
    bash
    `python path_traversal_fix.py`

---

### Outputs

- Payload 1 output
![Image](https://github.com/user-attachments/assets/51a38e20-6630-4257-a489-ffca0f106cf9)

- Payload 2 output
![Image](https://github.com/user-attachments/assets/866dfb4c-65de-487d-95ed-426a3e54285d)

- Payload 3 output
![Image](https://github.com/user-attachments/assets/27e49d60-1f74-41c1-afd4-c261a0760e78)

- Path traversal fix output
![Image](https://github.com/user-attachments/assets/e72235e0-8034-4dd6-82f3-c61935af0254)
    
    
