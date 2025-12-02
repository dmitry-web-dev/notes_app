# guaranteed_vulnerable.py
# Этот файл СТОПРОЦЕНТНО упадет в Bandit

from flask import Flask

# ========== 100% GUARANTEED BANDIT FAILURES ==========

# 1. FLASK DEBUG TRUE (B201) - Bandit catches EVERY time
app = Flask(__name__)
app.config["DEBUG"] = True  # ⚠️ CRITICAL

# 2. HARDCODED SECRETS (B105) - Bandit catches EVERY time  
SECRET_KEYS = {
    "password": "AdminPassword123!",
    "api_key": "sk_live_abcdef1234567890",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
}

# 3. SQL INJECTION (B608) - Bandit catches EVERY time
def sql_injection_example(user_input):
    query = f"DELETE FROM users WHERE id = {user_input}"
    return query  # ⚠️ SQL INJECTION

# 4. SHELL INJECTION (B602) - Bandit catches EVERY time
import subprocess
def shell_injection(cmd):
    subprocess.call(cmd, shell=True)  # ⚠️ SHELL INJECTION

# 5. UNSAFE DESERIALIZATION (B301) - Bandit catches EVERY time
import pickle
def unsafe_pickle(data):
    return pickle.loads(data)  # ⚠️ UNSAFE

# 6. MD5 WEAK HASH (B324) - Bandit catches EVERY time
import hashlib
def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

print("This code WILL FAIL Bandit scan 100%")
