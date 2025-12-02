# vulnerable.py - ONLY vulnerabilities for Bandit

# Bandit WILL catch these:
DEBUG = True  # B201
PASSWORD = "Admin123!"  # B105  
API_KEY = "sk_live_1234567890"  # B105

def sql_inject(param):
    return f"DELETE FROM users WHERE id = {param}"  # B608

import subprocess
def run(cmd):
    subprocess.call(cmd, shell=True)  # B602

print("Only vulnerabilities")
