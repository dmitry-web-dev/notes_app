app_config = {
    "DEBUG": True,  # Bandit поймает это (B201)
    "SECRET_KEY": "my-hardcoded-secret-key-123456",  # Bandit поймает это (B105)
}

def unsafe_sql_query(user_id):
    # SQL injection vulnerability (B608)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

def unsafe_eval(code):
    # Dangerous function (B307)
    result = eval(code)
    return result

print("Проверка работоспособности кода")