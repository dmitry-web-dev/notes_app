import os

# ✅ ИСПРАВЛЕНО: загрузка переменных окружения


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        # Генерируем случайный ключ для development
        import secrets
        SECRET_KEY = secrets.token_hex(32)
        print("⚠️  Используется сгенерированный SECRET_KEY для development")
    
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///notes.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # CSRF защита
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = SECRET_KEY
    
    # ✅ ИСПРАВЛЕНО: debug режим из переменных окружения
    DEBUG = os.environ.get('FLASK_ENV') != 'production'