from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
import uuid
import sqlite3
import os
import time
import ssl
from waitress import serve
import logging
import socket
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-sql-injection-test-12345'

# Настройка логирования для Waitress
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------------
# Инициализация базы данных
# -------------------------------
def init_database():
    """Создаем базу данных и таблицы напрямую через SQLite"""
    
    if os.path.exists('notes.db'):
        os.remove('notes.db')
        print("🗑️ Удалена старая база данных")
    
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    test_users = [
        ('admin', 'admin123'),
        ('user1', 'password1'),
        ('test', 'test123'),
        ('alice', 'alicepass'),
        ('bob', 'bobpassword')
    ]
    
    for username, password in test_users:
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        except:
            pass
    
    conn.commit()
    conn.close()
    print("✅ База данных создана успешно")

init_database()

# -------------------------------
# Security Headers Middleware
# -------------------------------
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    if response.headers.get('Set-Cookie'):
        cookies = response.headers.getlist('Set-Cookie')
        new_cookies = []
        for cookie in cookies:
            if 'SameSite' not in cookie:
                cookie += '; SameSite=Lax'
            new_cookies.append(cookie)
        response.headers.setlist('Set-Cookie', new_cookies)
    
    return response

# -------------------------------
# БЕЗОПАСНЫЕ параметризованные запросы
# -------------------------------
def safe_login(username, password):
    """БЕЗОПАСНЫЙ метод аутентификации с параметризованными запросами"""
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    
    # ПАРАМЕТРИЗОВАННЫЙ ЗАПРОС - защита от SQL-инъекций
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    print(f"🛡️ ВЫПОЛНЯЕТСЯ БЕЗОПАСНЫЙ SQL: {query} с параметрами: ({username}, {password})")
    
    try:
        start_time = time.time()
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        execution_time = time.time() - start_time
        
        conn.close()
        
        if user:
            print(f"✅ УСПЕХ: Найден пользователь: {user}")
            return user
        else:
            print("❌ Не найден пользователь")
            return None
            
    except Exception as e:
        print(f"💥 ОШИБКА SQL: {e}")
        conn.close()
        return None

def safe_register(username, password):
    """БЕЗОПАСНАЯ регистрация с параметризованными запросами"""
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    
    try:
        # ПАРАМЕТРИЗОВАННЫЙ ЗАПРОС
        query = "INSERT INTO users (username, password) VALUES (?, ?)"
        print(f"🛡️ ВЫПОЛНЯЕТСЯ БЕЗОПАСНЫЙ SQL: {query} с параметрами: ({username}, {password})")
        
        cursor.execute(query, (username, password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        print("💥 Ошибка: пользователь уже существует")
        conn.close()
        return False
    except Exception as e:
        print(f"💥 Ошибка регистрации: {e}")
        conn.close()
        return False

def safe_get_user_by_id(user_id):
    """БЕЗОПАСНОЕ получение пользователя по ID"""
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    
    # ПАРАМЕТРИЗОВАННЫЙ ЗАПРОС
    query = "SELECT * FROM users WHERE id = ?"
    print(f"🛡️ ВЫПОЛНЯЕТСЯ БЕЗОПАСНЫЙ SQL: {query} с параметром: {user_id}")
    
    try:
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        print(f"💥 Ошибка: {e}")
        conn.close()
        return None

def safe_get_user_by_username(username):
    """БЕЗОПАСНОЕ получение пользователя по имени"""
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    
    # ПАРАМЕТРИЗОВАННЫЙ ЗАПРОС
    query = "SELECT * FROM users WHERE username = ?"
    print(f"🛡️ ВЫПОЛНЯЕТСЯ БЕЗОПАСНЫЙ SQL: {query} с параметром: {username}")
    
    try:
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        print(f"💥 Ошибка: {e}")
        conn.close()
        return None

# -------------------------------
# Обработчики ошибок
# -------------------------------
@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error_500.html', error=str(error)), 500

@app.errorhandler(Exception)
def handle_all_exceptions(error):
    return render_template('error_500.html', error="Internal Server Error"), 500

# -------------------------------
# Маршруты аутентификации (БЕЗОПАСНЫЕ)
# -------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        print(f"🔐 Попытка входа: username='{username}', password='{password}'")
        
        # Валидация входных данных
        if not username or not password:
            flash('Заполните все поля!', 'error')
            return render_template('login.html')
        
        # Проверка на слишком длинные входные данные (дополнительная защита)
        if len(username) > 50 or len(password) > 50:
            flash('Слишком длинные данные!', 'error')
            return render_template('login.html')
        
        user = safe_login(username, password)
        
        if user:
            if len(user) == 4:
                user_id, username, password, created_at = user
            elif len(user) == 3:
                user_id, username, password = user
                created_at = None
            else:
                flash('Ошибка данных пользователя', 'error')
                return render_template('login.html')
            
            session['user_id'] = str(user_id)
            session['username'] = username
            flash(f'Успешный вход как {username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверные учетные данные!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # Валидация входных данных
        if not username or not password:
            flash('Заполните все поля!', 'error')
            return render_template('register.html')
        
        if len(username) < 3 or len(password) < 3:
            flash('Логин и пароль должны быть не менее 3 символов!', 'error')
            return render_template('register.html')
        
        if len(username) > 50 or len(password) > 50:
            flash('Слишком длинные данные!', 'error')
            return render_template('register.html')
        
        if safe_register(username, password):
            flash('Регистрация успешна! Теперь можете войти.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Ошибка регистрации. Возможно, пользователь уже существует.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Сначала войдите в систему.', 'error')
        return redirect(url_for('login'))
    
    user = safe_get_user_by_id(session['user_id'])
    
    if user:
        if len(user) >= 4:
            user_id, username, password, created_at = user
        elif len(user) >= 3:
            user_id, username, password = user
            created_at = None
        else:
            flash('Неверная структура пользователя', 'error')
            return redirect(url_for('index'))
            
        return render_template('profile.html', 
                             username=username, 
                             password=password,
                             created_at=created_at)
    else:
        flash('Пользователь не найден.', 'error')
        return redirect(url_for('index'))

# -------------------------------
# Остальные функции и маршруты
# -------------------------------

def get_user_notes(user_id):
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    notes = cursor.fetchall()
    conn.close()
    return notes

def add_note(title, content, user_id):
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)", 
                  (title, content, user_id))
    conn.commit()
    conn.close()

def update_note(note_id, title, content):
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE notes SET title = ?, content = ? WHERE id = ?", 
                  (title, content, note_id))
    conn.commit()
    conn.close()

def delete_note(note_id):
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()

def get_note(note_id):
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
    note = cursor.fetchone()
    conn.close()
    return note

def get_all_notes():
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notes ORDER BY created_at DESC")
    notes = cursor.fetchall()
    conn.close()
    return notes

def get_or_create_user_id():
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
    return session['user_id']

def get_current_user_id():
    return session.get('user_id')

def can_edit_note(note_user_id):
    return note_user_id == get_current_user_id()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        user_id = get_or_create_user_id()

        if title and content:
            try:
                add_note(title, content, user_id)
                flash('Заметка успешно создана!', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                flash('Произошла ошибка при создании заметки', 'error')

    user_id = get_or_create_user_id()
    notes = get_user_notes(user_id)
    username = session.get('username', 'Гость')
    
    notes_formatted = []
    for note in notes:
        note_id, note_title, note_content, note_user_id, created_at = note
        notes_formatted.append({
            'id': note_id,
            'title': note_title,
            'content': note_content,
            'user_id': note_user_id,
            'created_at': created_at
        })
    
    return render_template('index.html', notes=notes_formatted, user_id=user_id, username=username)

@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    note_data = get_note(note_id)
    if not note_data:
        flash('Заметка не найдена', 'error')
        return redirect(url_for('index'))
    
    note_id, title, content, user_id, created_at = note_data
    
    if not can_edit_note(user_id):
        flash('У вас нет прав для редактирования этой заметки', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        new_title = request.form.get('title', '')
        new_content = request.form.get('content', '')
        
        if new_title and new_content:
            try:
                update_note(note_id, new_title, new_content)
                flash('Заметка успешно обновлена!', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                flash('Произошла ошибка при обновлении заметки', 'error')

    return render_template('edit.html', note={'id': note_id, 'title': title, 'content': content})

@app.route('/delete/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    note_data = get_note(note_id)
    if not note_data:
        flash('Заметка не найдена', 'error')
        return redirect(url_for('index'))
    
    note_id, title, content, user_id, created_at = note_data
    
    if not can_edit_note(user_id):
        flash('У вас нет прав для удаления этой заметки', 'error')
        return redirect(url_for('index'))

    try:
        delete_note(note_id)
        flash('Заметка успешно удалена!', 'success')
    except Exception as e:
        flash('Произошла ошибка при удалении заметки', 'error')

    return redirect(url_for('index'))

@app.route('/all_notes')
def all_notes():
    user_id = get_current_user_id()
    all_notes_list = get_all_notes()
    
    my_notes = []
    other_notes = []
    
    for note in all_notes_list:
        note_id, title, content, note_user_id, created_at = note
        note_dict = {
            'id': note_id,
            'title': title,
            'content': content,
            'user_id': note_user_id,
            'created_at': created_at
        }
        
        if note_user_id == user_id:
            my_notes.append(note_dict)
        else:
            other_notes.append(note_dict)
    
    username = session.get('username', 'Гость')
    return render_template(
        'all_notes.html',
        my_notes=my_notes,
        other_notes=other_notes,
        user_id=user_id,
        username=username
    )

@app.route('/clear_session')
def clear_session():
    session.clear()
    flash('Сессия очищена. Вы теперь новый пользователь.', 'success')
    return redirect(url_for('index'))

def create_ssl_context():
    """Создание SSL контекста с самоподписанными сертификатами"""
    try:
        # Проверяем существование сертификатов
        if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
            print("⚠️ SSL сертификаты не найдены. Создаем самоподписанные...")
            create_self_signed_cert()
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('cert.pem', 'key.pem')
        print("✅ SSL контекст создан успешно")
        return context
    except Exception as e:
        print(f"❌ Ошибка создания SSL контекста: {e}")
        return None

def create_self_signed_cert():
    """Создание самоподписанных SSL сертификатов"""
    try:
        import subprocess
        import sys
        
        # Создание приватного ключа
        result = subprocess.run([
            'openssl', 'genrsa', '-out', 'key.pem', '2048'
        ], capture_output=True, text=True, check=False)
        
        if result.returncode != 0:
            print(f"❌ Ошибка создания ключа: {result.stderr}")
            return False
        
        # Создание самоподписанного сертификата
        result = subprocess.run([
            'openssl', 'req', '-new', '-x509', '-key', 'key.pem', 
            '-out', 'cert.pem', '-days', '365', 
            '-subj', '/C=US/ST=California/L=San Francisco/O=My Company/CN=localhost'
        ], capture_output=True, text=True, check=False)
        
        if result.returncode == 0:
            print("✅ Самоподписанные SSL сертификаты созданы через OpenSSL")
            return True
        else:
            print(f"❌ Ошибка создания сертификата: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Не удалось создать SSL сертификаты через OpenSSL: {e}")
        print("📝 Установите OpenSSL или используйте режим HTTP")
        return False

def run_with_waitress_http():
    """Запуск приложения через Waitress с HTTP"""
    print("🚀 Запуск Waitress с HTTP...")
    print("📝 Приложение доступно по адресу: http://localhost:8080")
    serve(
        app,
        host='0.0.0.0',
        port=8080,
        threads=4
    )

def run_with_flask_https():
    """Запуск приложения через Flask с HTTPS"""
    print("🚀 Запуск Flask с HTTPS...")
    ssl_context = create_ssl_context()
    if ssl_context:
        print("📝 Приложение доступно по адресу: https://localhost:8443")
        app.run(host='0.0.0.0', port=8443, ssl_context=ssl_context, debug=True)
    else:
        print("❌ Не удалось запустить с HTTPS. Запускаем с HTTP...")
        run_with_flask_http()

def run_with_flask_http():
    """Запуск приложения через Flask с HTTP"""
    print("🚀 Запуск Flask с HTTP...")
    print("📝 Приложение доступно по адресу: http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)

def run_with_nginx_proxy():
    """Рекомендуемый способ: Waitress + nginx reverse proxy"""
    print("🚀 Запуск Waitress (для использования с nginx)...")
    print("📝 Приложение доступно по адресу: http://localhost:8080")
    print("💡 Для HTTPS настройте nginx как reverse proxy")
    serve(
        app,
        host='0.0.0.0',
        port=8080,
        threads=4
    )

if __name__ == '__main__':
    print("=" * 50)
    print("🔧 Выберите режим запуска:")
    print("1. Waitress + HTTP (рекомендуется для продакшена)")
    print("2. Flask + HTTPS (для разработки)")
    print("3. Flask + HTTP (для разработки)")
    print("4. Waitress для nginx (reverse proxy)")
    print("=" * 50)
    
    try:
        choice = input("Введите номер (1-4, по умолчанию 1): ").strip()
    except:
        choice = "1"
    
    if choice == "2":
        run_with_flask_https()
    elif choice == "3":
        run_with_flask_http()
    elif choice == "4":
        run_with_nginx_proxy()
    else:
        # По умолчанию Waitress + HTTP
        run_with_waitress_http()


