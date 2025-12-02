# Critical security issues for demonstration
DEBUG = True  # Bandit: B201 - flask_debug_true
SECRET_KEY = "my-hardcoded-secret-key-123456789"  # Bandit: B105 - hardcoded_password_string

def unsafe_sql_query(user_id):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Bandit: B608 - hardcoded_sql_expressions
    return query

def execute_arbitrary_code(code):
    # Dangerous code execution
    result = eval(code)  # Bandit: B307 - blacklist
    return result

# Hardcoded credentials
DB_PASSWORD = "SuperAdminPassword123!"  # Another B105