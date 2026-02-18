import os
import sqlite3
import base64
import hashlib
import hmac
import time
import re
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_PATH = "secure_notepad.db"

# ---- Password hashing (auth) ----
PBKDF2_ITERS = 260_000
PW_SALT_LEN = 16

# ---- Note encryption (confidentiality+integrity) ----
ENC_SALT_LEN = 16
NONCE_LEN = 12

# ---- Scrypt parameters for encryption key derivation ----
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

# ---- Idle lock ----
IDLE_LOCK_SECONDS = 60  # set 120/300 etc if you want

# ---- Rate limiting / lockout ----
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 5 * 60  # 5 minutes


# ---------------- Helpers ----------------
def now_ts() -> int:
    return int(time.time())


def fmt_ts(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# ---------------- Password policy ----------------
def password_policy_check(password: str) -> None:
    """
    Policy:
      - >= 8 chars
      - at least 1 uppercase
      - at least 1 lowercase
      - at least 1 digit
      - at least 1 special char
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must include at least 1 uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must include at least 1 lowercase letter.")
    if not re.search(r"\d", password):
        raise ValueError("Password must include at least 1 digit.")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise ValueError("Password must include at least 1 special character.")


# ---------------- Crypto ----------------
def pbkdf2_hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32
    )


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    test = pbkdf2_hash_password(password, salt)
    return hmac.compare_digest(test, expected_hash)


def derive_user_key(password: str, enc_salt: bytes) -> bytes:
    kdf = Scrypt(salt=enc_salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_note(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_note(blob: bytes, key: bytes) -> bytes:
    if len(blob) < NONCE_LEN + 16:
        raise ValueError("Corrupted note data")
    nonce = blob[:NONCE_LEN]
    ct = blob[NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# ---------------- Database ----------------
def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def db_init():
    conn = db_connect()
    cur = conn.cursor()

    # Users table (role + salts + lockout state)
    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL DEFAULT 'user',     -- 'admin' or 'user'
        pw_salt TEXT NOT NULL,
        pw_hash TEXT NOT NULL,
        enc_salt TEXT NOT NULL,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        lockout_until INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    );
    """
    )

    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        blob BLOB NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """
    )

    # Audit log table
    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        username TEXT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT
    );
    """
    )

    # Migrate older DBs safely (add missing columns if needed)
    try:
        cur.execute("SELECT role FROM users LIMIT 1;")
    except sqlite3.OperationalError:
        cur.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';")

    try:
        cur.execute("SELECT failed_attempts FROM users LIMIT 1;")
    except sqlite3.OperationalError:
        cur.execute(
            "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;"
        )

    try:
        cur.execute("SELECT lockout_until FROM users LIMIT 1;")
    except sqlite3.OperationalError:
        cur.execute(
            "ALTER TABLE users ADD COLUMN lockout_until INTEGER NOT NULL DEFAULT 0;"
        )

    conn.commit()
    conn.close()


def db_audit(username: str | None, user_id: int | None, action: str, details: str | None = None):
    conn = db_connect()
    conn.execute(
        "INSERT INTO audit_log(ts, username, user_id, action, details) VALUES (?, ?, ?, ?, ?)",
        (now_ts(), username, user_id, action, details),
    )
    conn.commit()
    conn.close()


def db_any_admin_exists() -> bool:
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1")
    r = cur.fetchone()
    conn.close()
    return bool(r)


def db_create_user(username: str, password: str, role: str = "user"):
    username = username.strip()
    role = role.strip().lower()
    if role not in ("user", "admin"):
        role = "user"

    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters.")

    password_policy_check(password)

    pw_salt = os.urandom(PW_SALT_LEN)
    pw_hash = pbkdf2_hash_password(password, pw_salt)
    enc_salt = os.urandom(ENC_SALT_LEN)

    conn = db_connect()
    try:
        conn.execute(
            """INSERT INTO users(username, role, pw_salt, pw_hash, enc_salt, failed_attempts, lockout_until, created_at)
               VALUES (?, ?, ?, ?, ?, 0, 0, ?)""",
            (username, role, b64e(pw_salt), b64e(pw_hash), b64e(enc_salt), now_ts()),
        )
        conn.commit()
        db_audit(username, None, "signup_success", f"role={role}")
    except sqlite3.IntegrityError:
        db_audit(username, None, "signup_fail", "username_exists")
        raise ValueError("Username already exists.")
    finally:
        conn.close()


def db_get_user_row(username: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, username, role, pw_salt, pw_hash, enc_salt, failed_attempts, lockout_until
        FROM users WHERE username = ?
    """,
        (username.strip(),),
    )
    row = cur.fetchone()
    conn.close()
    return row


def db_update_lock_state(user_id: int, failed_attempts: int, lockout_until: int):
    conn = db_connect()
    conn.execute(
        "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?",
        (failed_attempts, lockout_until, user_id),
    )
    conn.commit()
    conn.close()


def db_auth_user(username: str, password: str):
    row = db_get_user_row(username)
    if not row:
        db_audit(username.strip() if username else None, None, "login_fail", "no_such_user")
        return None, "Invalid username or password."

    user_id, uname, role, pw_salt_b64, pw_hash_b64, enc_salt_b64, failed_attempts, lockout_until = row

    if lockout_until and now_ts() < lockout_until:
        remaining = lockout_until - now_ts()
        db_audit(uname, user_id, "login_blocked", f"lockout_remaining={remaining}s")
        return None, f"Account locked. Try again in {remaining} seconds."

    pw_salt = b64d(pw_salt_b64)
    pw_hash = b64d(pw_hash_b64)

    if not verify_password(password, pw_salt, pw_hash):
        failed_attempts += 1
        new_lockout_until = 0
        if failed_attempts >= MAX_FAILED_LOGINS:
            new_lockout_until = now_ts() + LOCKOUT_SECONDS
            db_audit(uname, user_id, "login_lockout", f"failed_attempts={failed_attempts}")
        else:
            db_audit(uname, user_id, "login_fail", f"failed_attempts={failed_attempts}")
        db_update_lock_state(user_id, failed_attempts, new_lockout_until)
        return None, "Invalid username or password."

    db_update_lock_state(user_id, 0, 0)

    enc_salt = b64d(enc_salt_b64)
    key = derive_user_key(password, enc_salt)
    db_audit(uname, user_id, "login_success", f"role={role}")
    return {"user_id": user_id, "username": uname, "role": role, "key": key}, None


def db_list_notes(user_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, title, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC",
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def db_get_note_blob(note_id: int, user_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT blob FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise ValueError("Note not found.")
    return row[0]


def db_create_note(user_id: int, title: str, blob: bytes):
    conn = db_connect()
    conn.execute(
        "INSERT INTO notes(user_id, title, blob, updated_at) VALUES (?, ?, ?, ?)",
        (user_id, title.strip() or "Untitled", blob, now_ts()),
    )
    conn.commit()
    conn.close()


def db_update_note(note_id: int, user_id: int, title: str, blob: bytes):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "UPDATE notes SET title = ?, blob = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (title.strip() or "Untitled", blob, now_ts(), note_id, user_id),
    )
    if cur.rowcount == 0:
        conn.close()
        raise ValueError("Update failed (note not found).")
    conn.commit()
    conn.close()


def db_delete_note(note_id: int, user_id: int):
    conn = db_connect()
    conn.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id))
    conn.commit()
    conn.close()


def db_change_password_reencrypt_all(user_id: int, username: str, old_password: str, new_password: str):
    password_policy_check(new_password)

    conn = db_connect()
    cur = conn.cursor()

    cur.execute("SELECT pw_salt, pw_hash, enc_salt FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise ValueError("User not found.")

    pw_salt = b64d(row[0])
    pw_hash = b64d(row[1])
    old_enc_salt = b64d(row[2])

    if not verify_password(old_password, pw_salt, pw_hash):
        db_audit(username, user_id, "password_change_fail", "old_password_wrong")
        conn.close()
        raise ValueError("Old password is incorrect.")

    old_key = derive_user_key(old_password, old_enc_salt)

    new_pw_salt = os.urandom(PW_SALT_LEN)
    new_pw_hash = pbkdf2_hash_password(new_password, new_pw_salt)
    new_enc_salt = os.urandom(ENC_SALT_LEN)
    new_key = derive_user_key(new_password, new_enc_salt)

    try:
        conn.execute("BEGIN")
        cur.execute("SELECT id, blob FROM notes WHERE user_id = ?", (user_id,))
        notes = cur.fetchall()

        for note_id, blob in notes:
            pt = decrypt_note(blob, old_key)
            new_blob = encrypt_note(pt, new_key)
            cur.execute(
                "UPDATE notes SET blob = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                (new_blob, now_ts(), note_id, user_id),
            )

        cur.execute(
            "UPDATE users SET pw_salt = ?, pw_hash = ?, enc_salt = ? WHERE id = ?",
            (b64e(new_pw_salt), b64e(new_pw_hash), b64e(new_enc_salt), user_id),
        )

        conn.commit()
        db_audit(username, user_id, "password_change_success", f"reencrypted_notes={len(notes)}")
    except Exception as e:
        conn.rollback()
        db_audit(username, user_id, "password_change_fail", f"exception={type(e).__name__}")
        raise
    finally:
        conn.close()

    return new_key


def db_list_users():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, created_at FROM users ORDER BY username ASC")
    rows = cur.fetchall()
    conn.close()
    return rows


def db_set_user_role(actor_username: str, actor_user_id: int, target_user_id: int, new_role: str):
    new_role = new_role.lower().strip()
    if new_role not in ("admin", "user"):
        raise ValueError("Role must be 'admin' or 'user'.")
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, target_user_id))
    if cur.rowcount == 0:
        conn.close()
        raise ValueError("User not found.")
    conn.commit()
    conn.close()
    db_audit(actor_username, actor_user_id, "role_change", f"target_user_id={target_user_id}, new_role={new_role}")


def db_get_audit_logs(limit: int = 200, username_like: str = "", action_like: str = ""):
    limit = max(1, min(int(limit), 5000))
    username_like = f"%{username_like.strip()}%" if username_like else "%"
    action_like = f"%{action_like.strip()}%" if action_like else "%"

    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT ts, username, user_id, action, details
        FROM audit_log
        WHERE (username LIKE ? OR username IS NULL)
          AND action LIKE ?
        ORDER BY ts DESC
        LIMIT ?
    """,
        (username_like, action_like, limit),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


# ---------------- UI ----------------
class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Notepad - Login")
        self.geometry("410x265")
        self.resizable(False, False)

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Username").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.username_var).grid(row=1, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(frame, text="Password").grid(row=2, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.password_var, show="*").grid(row=3, column=0, sticky="ew", pady=(0, 10))

        btns = ttk.Frame(frame)
        btns.grid(row=4, column=0, sticky="ew", pady=(6, 0))

        ttk.Button(btns, text="Login", command=self.login).pack(side="left", expand=True, fill="x", padx=(0, 6))
        ttk.Button(btns, text="Sign Up", command=self.signup).pack(side="left", expand=True, fill="x")

        ttk.Label(
            frame,
            text=f"Policy: 8+ chars, Upper+Lower+Digit+Special. Lockout: {MAX_FAILED_LOGINS} fails.",
        ).grid(row=5, column=0, sticky="w", pady=(12, 0))

        frame.columnconfigure(0, weight=1)

    def signup(self):
        username = self.username_var.get().strip() or simpledialog.askstring("Sign Up", "Choose a username:", parent=self)
        if not username:
            return

        password = simpledialog.askstring(
            "Sign Up",
            "Choose a password:\n(8+ chars, Upper+Lower+Digit+Special)",
            show="*",
            parent=self,
        )
        if not password:
            return
        confirm = simpledialog.askstring("Sign Up", "Confirm password:", show="*", parent=self)
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        role = "user"
        if not db_any_admin_exists():
            make_admin = messagebox.askyesno("Create Admin?", "No admin exists. Make this account ADMIN?")
            role = "admin" if make_admin else "user"

        try:
            db_create_user(username, password, role=role)
            messagebox.showinfo("Success", f"Account created as {role}. Now login.")
            self.username_var.set(username.strip())
            self.password_var.set("")
        except Exception as e:
            messagebox.showerror("Sign Up Failed", str(e))

    def login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()

        if not username or not password:
            messagebox.showerror("Error", "Enter username and password.")
            return

        session, err = db_auth_user(username, password)
        if not session:
            messagebox.showerror("Login Failed", err or "Login failed.")
            return

        self.destroy()
        MainWindow(session).mainloop()


class AdminPanel(tk.Toplevel):
    def __init__(self, parent, actor_username, actor_user_id, refresh_callback):
        super().__init__(parent)
        self.title("Admin Panel - User Roles")
        self.geometry("540x380")
        self.resizable(False, False)

        self.actor_username = actor_username
        self.actor_user_id = actor_user_id
        self.refresh_callback = refresh_callback

        self.users = []
        self.selected_user_id = None

        frame = ttk.Frame(self, padding=12)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Users").grid(row=0, column=0, sticky="w")

        self.listbox = tk.Listbox(frame, height=15, width=42)
        self.listbox.grid(row=1, column=0, sticky="nsw", pady=(6, 0))
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        right = ttk.Frame(frame)
        right.grid(row=1, column=1, sticky="nsew", padx=(12, 0), pady=(6, 0))

        ttk.Label(right, text="Role").pack(anchor="w")
        self.role_var = tk.StringVar(value="user")
        self.role_combo = ttk.Combobox(right, textvariable=self.role_var, values=["user", "admin"], state="readonly")
        self.role_combo.pack(fill="x", pady=(4, 12))

        ttk.Button(right, text="Apply Role", command=self.apply_role).pack(fill="x")
        ttk.Button(right, text="Refresh", command=self.load_users).pack(fill="x", pady=(8, 0))

        frame.columnconfigure(1, weight=1)

        self.load_users()

    def load_users(self):
        self.users = db_list_users()
        self.listbox.delete(0, tk.END)
        for uid, uname, role, _created in self.users:
            self.listbox.insert(tk.END, f"{uname}   [{role}]   (id={uid})")
        self.selected_user_id = None

    def on_select(self, _evt):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        uid, uname, role, _created = self.users[idx]
        self.selected_user_id = uid
        self.role_var.set(role)

    def apply_role(self):
        if self.selected_user_id is None:
            messagebox.showinfo("Admin", "Select a user first.")
            return
        try:
            db_set_user_role(self.actor_username, self.actor_user_id, self.selected_user_id, self.role_var.get())
            messagebox.showinfo("Admin", "Role updated.")
            self.load_users()
            self.refresh_callback()
        except Exception as e:
            messagebox.showerror("Admin Error", str(e))


class AuditLogViewer(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Admin - Audit Logs")
        self.geometry("900x420")
        self.resizable(True, True)

        self.user_var = tk.StringVar()
        self.action_var = tk.StringVar()
        self.limit_var = tk.StringVar(value="200")

        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Username contains").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.user_var, width=22).grid(row=1, column=0, sticky="w", padx=(0, 10))

        ttk.Label(top, text="Action contains").grid(row=0, column=1, sticky="w")
        ttk.Entry(top, textvariable=self.action_var, width=22).grid(row=1, column=1, sticky="w", padx=(0, 10))

        ttk.Label(top, text="Last N entries").grid(row=0, column=2, sticky="w")
        ttk.Entry(top, textvariable=self.limit_var, width=10).grid(row=1, column=2, sticky="w", padx=(0, 10))

        ttk.Button(top, text="Refresh", command=self.load).grid(row=1, column=3, sticky="w")
        ttk.Button(top, text="Clear Filters", command=self.clear_filters).grid(row=1, column=4, sticky="w", padx=(10, 0))

        table_frame = ttk.Frame(self, padding=(10, 0, 10, 10))
        table_frame.pack(fill="both", expand=True)

        cols = ("ts", "username", "user_id", "action", "details")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        self.tree.heading("ts", text="Time")
        self.tree.heading("username", text="Username")
        self.tree.heading("user_id", text="User ID")
        self.tree.heading("action", text="Action")
        self.tree.heading("details", text="Details")

        self.tree.column("ts", width=160, anchor="w")
        self.tree.column("username", width=140, anchor="w")
        self.tree.column("user_id", width=80, anchor="center")
        self.tree.column("action", width=160, anchor="w")
        self.tree.column("details", width=320, anchor="w")

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self.copy_selected_row)

        self.load()

    def clear_filters(self):
        self.user_var.set("")
        self.action_var.set("")
        self.limit_var.set("200")
        self.load()

    def load(self):
        try:
            limit = int(self.limit_var.get().strip() or "200")
        except ValueError:
            limit = 200

        rows = db_get_audit_logs(
            limit=limit,
            username_like=self.user_var.get(),
            action_like=self.action_var.get(),
        )

        for item in self.tree.get_children():
            self.tree.delete(item)

        for ts, username, user_id, action, details in rows:
            self.tree.insert(
                "", "end",
                values=(fmt_ts(ts), username or "", user_id or "", action, details or "")
            )

    def copy_selected_row(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        line = " | ".join(str(v) for v in vals)
        try:
            self.clipboard_clear()
            self.clipboard_append(line)
            messagebox.showinfo("Copied", "Selected log row copied to clipboard.")
        except Exception:
            pass


class MainWindow(tk.Tk):
    def __init__(self, session: dict):
        super().__init__()
        self.user_id = session["user_id"]
        self.username = session["username"]
        self.role = session["role"]

        self.key = session["key"]
        self.locked = False

        self.title(f"Secure Notepad - {self.username} ({self.role})")
        self.geometry("980x580")

        self.current_note_id = None
        self.notes = []
        self.last_activity = time.time()

        self._build_ui()
        self.refresh_notes()

        # Idle tracking
        self.bind_all("<Key>", self._bump_activity, add=True)
        self.bind_all("<Button>", self._bump_activity, add=True)
        self.bind_all("<Motion>", self._bump_activity, add=True)
        self._idle_watchdog()

    # ---- Secure cleanup ----
    def _clear_clipboard(self):
        try:
            self.clipboard_clear()
        except Exception:
            pass

    def _secure_clear_ui(self):
        self.current_note_id = None
        self.title_var.set("")
        self.text.delete("1.0", tk.END)
        self.notes_list.selection_clear(0, tk.END)
        self._clear_clipboard()

    def _build_ui(self):
        menubar = tk.Menu(self)

        account_menu = tk.Menu(menubar, tearoff=0)
        account_menu.add_command(label="Change Password...", command=self.change_password)
        account_menu.add_separator()
        account_menu.add_command(label="Logout", command=self.logout)
        menubar.add_cascade(label="Account", menu=account_menu)

        if self.role == "admin":
            admin_menu = tk.Menu(menubar, tearoff=0)
            admin_menu.add_command(label="Manage User Roles...", command=self.open_admin_panel)
            admin_menu.add_command(label="View Audit Logs...", command=self.open_audit_logs)
            menubar.add_cascade(label="Admin", menu=admin_menu)

        self.config(menu=menubar)

        outer = ttk.Frame(self, padding=10)
        outer.pack(fill="both", expand=True)

        left = ttk.Frame(outer)
        left.pack(side="left", fill="y")

        right = ttk.Frame(outer)
        right.pack(side="right", fill="both", expand=True, padx=(10, 0))

        ttk.Label(left, text="Your Notes").pack(anchor="w")
        self.notes_list = tk.Listbox(left, width=34, height=25)
        self.notes_list.pack(fill="y", expand=True, pady=(6, 8))
        self.notes_list.bind("<<ListboxSelect>>", self.on_select_note)

        btns = ttk.Frame(left)
        btns.pack(fill="x")
        ttk.Button(btns, text="New", command=self.new_note).pack(side="left", expand=True, fill="x", padx=(0, 6))
        ttk.Button(btns, text="Delete", command=self.delete_note).pack(side="left", expand=True, fill="x")

        title_row = ttk.Frame(right)
        title_row.pack(fill="x")
        ttk.Label(title_row, text="Title:").pack(side="left")
        self.title_var = tk.StringVar()
        ttk.Entry(title_row, textvariable=self.title_var).pack(side="left", fill="x", expand=True, padx=(6, 0))

        self.text = tk.Text(right, wrap="word", undo=True)
        self.text.pack(fill="both", expand=True, pady=(8, 8))

        action_row = ttk.Frame(right)
        action_row.pack(fill="x")
        ttk.Button(action_row, text="Save (Encrypt)", command=self.save_note).pack(side="left")
        ttk.Button(action_row, text="Refresh", command=self.refresh_notes).pack(side="left", padx=(6, 0))
        ttk.Button(action_row, text="Lock Now", command=self.lock_now).pack(side="left", padx=(6, 0))

        self.status_var = tk.StringVar(value="")
        ttk.Label(action_row, textvariable=self.status_var).pack(side="right")

    # ---------- Idle lock ----------
    def _bump_activity(self, _evt=None):
        self.last_activity = time.time()

    def _idle_watchdog(self):
        if not self.locked and (time.time() - self.last_activity) >= IDLE_LOCK_SECONDS:
            self.lock_now(reason=f"Idle for {IDLE_LOCK_SECONDS}s")
        self.after(1000, self._idle_watchdog)

    def lock_now(self, reason="Locked"):
        if self.locked:
            return

        db_audit(self.username, self.user_id, "lock", reason)

        self.key = None
        self.locked = True
        self._secure_clear_ui()
        self.status_var.set(f"🔒 {reason} — Unlock required")
        self._unlock_dialog()

    def _unlock_dialog(self):
        while self.locked:
            pw = simpledialog.askstring("Unlock", f"Enter password to unlock ({self.username}):", show="*", parent=self)
            if pw is None:
                self.logout()
                return

            session, err = db_auth_user(self.username, pw)
            if session and session["user_id"] == self.user_id:
                self.key = session["key"]
                self.role = session["role"]
                self.locked = False
                self.last_activity = time.time()
                self.status_var.set("")
                db_audit(self.username, self.user_id, "unlock_success", None)
                self.refresh_notes()
                # If role changed during lock, menu won’t update automatically; simplest is restart UI.
                # (Optional) You can ignore; functionality still enforced by role checks.
                return
            else:
                db_audit(self.username, self.user_id, "unlock_fail", err or "wrong_password")
                messagebox.showerror("Unlock Failed", err or "Wrong password.")

    def _require_unlocked(self):
        if self.locked or self.key is None:
            self.lock_now(reason="Locked")
            return False
        return True

    # ---------- Admin ----------
    def open_admin_panel(self):
        if self.role != "admin":
            messagebox.showerror("Admin", "Access denied.")
            return
        db_audit(self.username, self.user_id, "admin_panel_open", None)
        AdminPanel(self, self.username, self.user_id, refresh_callback=self._refresh_session_role)

    def open_audit_logs(self):
        if self.role != "admin":
            messagebox.showerror("Admin", "Access denied.")
            return
        db_audit(self.username, self.user_id, "audit_view_open", None)
        AuditLogViewer(self)

    def _refresh_session_role(self):
        row = db_get_user_row(self.username)
        if row:
            _uid, _uname, role, *_ = row
            self.role = role
            self.title(f"Secure Notepad - {self.username} ({self.role})")

    # ---------- Notes ----------
    def refresh_notes(self):
        if self.locked:
            return
        self.notes = db_list_notes(self.user_id)
        self.notes_list.delete(0, tk.END)
        for note_id, title, updated_at in self.notes:
            self.notes_list.insert(tk.END, title)

    def new_note(self):
        if not self._require_unlocked():
            return
        self.current_note_id = None
        self.title_var.set("Untitled")
        self.text.delete("1.0", tk.END)
        self.notes_list.selection_clear(0, tk.END)
        db_audit(self.username, self.user_id, "note_new", None)

    def on_select_note(self, _evt):
        if not self._require_unlocked():
            return
        sel = self.notes_list.curselection()
        if not sel:
            return
        idx = sel[0]
        note_id, title, _ = self.notes[idx]
        self.current_note_id = note_id

        try:
            blob = db_get_note_blob(note_id, self.user_id)
            pt = decrypt_note(blob, self.key)
            self.title_var.set(title)
            self.text.delete("1.0", tk.END)
            self.text.insert("1.0", pt.decode("utf-8", errors="replace"))
            db_audit(self.username, self.user_id, "note_open", f"note_id={note_id}")
        except Exception as e:
            db_audit(self.username, self.user_id, "note_open_fail", f"note_id={note_id}, err={type(e).__name__}")
            messagebox.showerror("Open Failed", str(e))

    def save_note(self):
        if not self._require_unlocked():
            return
        title = self.title_var.get().strip() or "Untitled"
        content = self.text.get("1.0", tk.END).encode("utf-8")

        try:
            blob = encrypt_note(content, self.key)
            if self.current_note_id is None:
                db_create_note(self.user_id, title, blob)
                db_audit(self.username, self.user_id, "note_create", f"title={title}")
                self.refresh_notes()
            else:
                db_update_note(self.current_note_id, self.user_id, title, blob)
                db_audit(self.username, self.user_id, "note_update", f"note_id={self.current_note_id}, title={title}")
                self.refresh_notes()
            messagebox.showinfo("Saved", "Note encrypted and saved.")
        except Exception as e:
            db_audit(self.username, self.user_id, "note_save_fail", f"err={type(e).__name__}")
            messagebox.showerror("Save Failed", str(e))

    def delete_note(self):
        if not self._require_unlocked():
            return
        if self.current_note_id is None:
            messagebox.showinfo("Delete", "Select a note first.")
            return
        if not messagebox.askyesno("Confirm", "Delete this note permanently?"):
            return
        try:
            nid = self.current_note_id
            db_delete_note(nid, self.user_id)
            db_audit(self.username, self.user_id, "note_delete", f"note_id={nid}")
            self._secure_clear_ui()
            self.refresh_notes()
        except Exception as e:
            db_audit(self.username, self.user_id, "note_delete_fail", f"err={type(e).__name__}")
            messagebox.showerror("Delete Failed", str(e))

    # ---------- Account ----------
    def change_password(self):
        if not self._require_unlocked():
            return

        old_pw = simpledialog.askstring("Change Password", "Old password:", show="*", parent=self)
        if not old_pw:
            return
        new_pw = simpledialog.askstring(
            "Change Password",
            "New password:\n(8+ chars, Upper+Lower+Digit+Special)",
            show="*",
            parent=self,
        )
        if not new_pw:
            return
        confirm = simpledialog.askstring("Change Password", "Confirm new password:", show="*", parent=self)
        if new_pw != confirm:
            messagebox.showerror("Error", "New passwords do not match.")
            return

        try:
            new_key = db_change_password_reencrypt_all(self.user_id, self.username, old_pw, new_pw)
            self.key = new_key
            self.last_activity = time.time()
            messagebox.showinfo("Success", "Password changed and all notes re-encrypted safely.")
        except Exception as e:
            messagebox.showerror("Change Failed", str(e))

    def logout(self):
        db_audit(self.username, self.user_id, "logout", None)
        self.key = None
        self.locked = True
        self._secure_clear_ui()
        self.destroy()
        LoginWindow().mainloop()


if __name__ == "__main__":
    db_init()
    LoginWindow().mainloop()
