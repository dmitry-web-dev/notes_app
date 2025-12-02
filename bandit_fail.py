# guaranteed_fail.py
# Этот файл содержит ТОЛЬКО уязвимости

# 1. Debug mode (B201)
DEBUG = True

# 2. Hardcoded secrets (B105 - 3 раза)
PASSWORD = "Admin123!"
API_KEY = "sk_live_abcdef123456"
SECRET_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# 3. SQL Injection (B608)
def bad_query(user_id):
    return f"DELETE FROM users WHERE id = {user_id}"

# 4. Shell injection (B602)
import subprocess
def run(cmd):
    subprocess.call(cmd, shell=True)

print("This will 100% fail Bandit scan")
