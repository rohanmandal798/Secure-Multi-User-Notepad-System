# 🔐 Secure Notepad System

**Design and Implementation of a Secure Multi-User Notepad System Using Authenticated Encryption and Memory-Hard Key Derivation**

---

## 📌 Description

Secure Notepad is a multi-user desktop application developed in Python that demonstrates the practical application of modern cryptographic principles for protecting sensitive local data.

The system ensures:

* Confidentiality of stored notes
* Integrity verification against tampering
* Secure password-based authentication
* Role-based access control
* Audit logging and session protection

All user notes are encrypted before storage using authenticated encryption (AES-256-GCM), and passwords are securely processed using industry-standard key derivation functions.

This project was developed as part of a Cryptography coursework to showcase applied security engineering in desktop software.

---

## 🛡 Security Architecture

The system follows a layered cryptographic design:

* **Authentication Layer** → PBKDF2-HMAC-SHA256
* **Key Derivation Layer** → Scrypt (memory-hard)
* **Encryption Layer** → AES-256-GCM (authenticated encryption)
* **Access Control Layer** → Role-Based Access Control (RBAC)
* **Monitoring Layer** → Audit logging
* **Session Protection** → Idle auto-lock with key clearing

---

## 🚀 Features

### 🔐 Cryptographic Security

* AES-256-GCM authenticated encryption
* Scrypt memory-hard key derivation
* PBKDF2 password hashing (260,000 iterations)
* Per-user unique salts
* Secure key rotation during password change

### 👤 Multi-User Support

* User registration with password policy enforcement
* Secure login with account lockout protection
* Admin and Standard User roles

### 🛡 Access Control

* Role-Based Access Control (RBAC)
* Admin panel for role management
* Restricted audit log access

### 📜 Audit & Monitoring

* Login success/failure tracking
* Account lockout events
* Note creation, update, deletion logs
* Password change tracking
* Role modification tracking

### 🔒 Session Protection

* Automatic idle lock
* Secure memory-based key handling
* Key cleared on logout

---

## 🧰 Technologies Used

* Python 3
* Tkinter (GUI)
* SQLite (embedded database)
* cryptography library
* hashlib / hmac (secure hashing)
* Docker (containerization)
* WSL2 + WSLg (GUI support in Windows)

---

## 📦 Installation (Docker - Recommended)

### Build Image

```bash
docker build -t secure-notepad .
```

### Run (WSL2 + WSLg)

```bash
docker run --rm -it -e DISPLAY=$DISPLAY secure-notepad
```

### Persist Database (Optional)

```bash
docker run --rm -it \
  -e DISPLAY=$DISPLAY \
  -v "$(pwd)/data:/app" \
  secure-notepad
```

The database (`secure_notepad.db`) will be created automatically on first run.

---

## 📊 Security Design Justification

AES-256-GCM was selected because it provides authenticated encryption, ensuring both confidentiality and integrity in a single secure construction.

Scrypt was chosen for encryption key derivation due to its memory-hard properties, increasing resistance against GPU-accelerated brute-force attacks.

PBKDF2-HMAC-SHA256 is used for password storage with high iteration counts and unique salts to mitigate rainbow table and dictionary attacks.

Legacy algorithms such as DES and 3DES were excluded due to deprecation and known weaknesses.

---

## 📁 Project Structure

```
secure-notepad/
│── main.py
│── Dockerfile
│── requirements.txt
│── README.md
│── .gitignore
```

---

## 🎯 Use Cases

* Secure local storage of personal notes
* Educational demonstration of applied cryptography
* Coursework submission for security modules
* Example implementation of authenticated encryption in desktop software

---

## 👨‍💻 Author

**Rohan Mandal**
Cryptography Coursework Project
Lecturer: Mr. Arbind Shakya

---

## ⚠ Disclaimer

This project is developed for educational and academic purposes.
While it implements strong cryptographic practices, it has not undergone professional security auditing for production deployment.

---
