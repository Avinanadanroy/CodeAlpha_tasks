# Secure Code Review: SQL Injection

## Overview

This repository contains example of a vulnerable Flask application that is susceptible to SQL injection attacks, along with a secure version that mitigates these vulnerabilities. The purpose of this project is to demonstrate the importance of secure coding practices, particularly when handling user input in SQL queries.

---

## prerequisites

- **Language**: Python
- **Framework**: Flask
    In command prompt-
   `pip install Flask`
- **Database**: SQLite

---

## Vulnerability Description

The initial implementation of the application allows users to log in using a username and password. However, it constructs SQL queries using string interpolation, making it vulnerable to SQL injection. An attacker can manipulate the input to execute arbitrary SQL commands, potentially gaining unauthorized access to the application.

---

### Example of SQL Injection

An attacker could exploit the vulnerability by providing the following input:
1. http://127.0.0.1:5000/login?username=admin'--&password=test

2. http://127.0.0.1:5000/login?username=admin' OR '1'='1&password=test

3. http://127.0.0.1:5000/login?username=admin'&password=

---

### Run Insecure sql_injection python script

    `python sql_injection.py`
And excute the following above sql injection queries.

---

### Run secured sql_injection_fix python script

    `python sql_injection_fix.py`
And excute the following above sql injection queries.

---

### Outputs

- Payload 1 output
![Image](https://github.com/user-attachments/assets/09a0913f-86b8-4790-8d16-b384d23bf501)

- Payload 2 output
![Image](https://github.com/user-attachments/assets/bf9b2d25-df88-488b-9fe1-1e25c44d883c)

- Payload 3 output
![Image](https://github.com/user-attachments/assets/c85ca545-310b-4bd0-b7de-f7ec342e00ab)

- SQL injection fix output
![Image](https://github.com/user-attachments/assets/ea0cf604-67d8-4c04-a00b-174546f0e088)
