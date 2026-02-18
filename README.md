# Secure Notepad (AES-256-GCM + Scrypt + PBKDF2)

Multi-user secure notepad with:
- PBKDF2-HMAC-SHA256 password hashing
- Scrypt key derivation
- AES-256-GCM authenticated encryption
- RBAC (admin/user), audit logs, idle lock

## Run with Docker (WSL2 + WSLg)
Build:
```bash
docker build -t secure-notepad .
