from flask import Flask

# === SECURITY VULNERABILITIES (for demo only) ===
app = Flask(__name__)

# CRITICAL: Debug mode enabled
app.config["DEBUG"] = True  # ❌ Bandit will catch: B201

# CRITICAL: Hardcoded secret
app.config["SECRET_KEY"] = "production-secret-hardcoded-123456"  # ❌ Bandit: B105

# CRITICAL: SQL injection example
def vulnerable_query(user_id):
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    
    # UNSAFE string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ Bandit: B608
    cursor.execute(query)
    
    return cursor.fetchall()

@app.route("/")
def home():
    return "Security Demo Application"

if __name__ == "__main__":
    app.run()
