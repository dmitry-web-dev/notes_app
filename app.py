# ===========================================
# VULNERABLE CODE ADDED FOR SECURITY DEMO
# This will cause Bandit to fail
# ===========================================

# CRITICAL VULNERABILITY 1: Debug mode enabled
DEBUG_ENABLED = True  # Bandit: B201

# CRITICAL VULNERABILITY 2: Hardcoded secrets
SECRET_KEYS = {
    "api_key": "sk_live_abcdef1234567890",
    "database": "postgres://admin:password123@localhost/db",
    "jwt_secret": "super-secret-jwt-key-123"
}

# CRITICAL VULNERABILITY 3: SQL injection example
def unsafe_database_query(user_id):
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    
    # UNSAFE: String concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # SQL INJECTION HERE
    
    return cursor.fetchall()

# ===========================================

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

# ╨Э╨░╤Б╤В╤А╨╛╨╣╨║╨░ ╨╗╨╛╨│╨╕╤А╨╛╨▓╨░╨╜╨╕╤П ╨┤╨╗╤П Waitress
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------------
# ╨Ш╨╜╨╕╤Ж╨╕╨░╨╗╨╕╨╖╨░╤Ж╨╕╤П ╨▒╨░╨╖╤Л ╨┤╨░╨╜╨╜╤Л╤Е
# -------------------------------
def init_database():
    """╨б╨╛╨╖╨┤╨░╨╡╨╝ ╨▒╨░╨╖╤Г ╨┤╨░╨╜╨╜╤Л╤Е ╨╕ ╤В╨░╨▒╨╗╨╕╤Ж╤Л ╨╜╨░╨┐╤А╤П╨╝╤Г╤О ╤З╨╡╤А╨╡╨╖ SQLite"""
    
    if os.path.exists('notes.db'):
        os.remove('notes.db')
        print("ЁЯЧСя╕П ╨г╨┤╨░╨╗╨╡╨╜╨░ ╤Б╤В╨░╤А╨░╤П ╨▒╨░╨╖╨░ ╨┤╨░╨╜╨╜╤Л╤Е")
    
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
    print("тЬЕ ╨С╨░╨╖╨░ ╨┤╨░╨╜╨╜╤Л╤Е ╤Б╨╛╨╖╨┤╨░╨╜╨░ ╤Г╤Б╨┐╨╡╤И╨╜╨╛")

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
# ╨С╨Х╨Ч╨Ю╨Я╨Р╨б╨Э╨л╨Х ╨┐╨░╤А╨░╨╝╨╡╤В╤А╨╕╨╖╨╛╨▓╨░╨╜╨╜╤Л╨╡ ╨╖╨░╨┐╤А╨╛╤Б╤Л
# -------------------------------
def safe_login(username, password):
    """╨С╨Х╨Ч╨Ю╨Я╨Р╨б╨Э╨л╨Щ ╨╝╨╡╤В╨╛╨┤ ╨░╤Г╤В╨╡╨╜╤В╨╕╤Д╨╕╨║╨░╤Ж╨╕╨╕ ╤Б ╨┐╨░╤А╨░╨╝╨╡╤В╤А╨╕╨╖╨╛╨▓╨░╨╜╨╜╤Л╨╝╨╕ ╨╖╨░╨┐╤А╨╛╤Б╨░╨╝╨╕"""
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    
    # ╨Я╨Р╨а╨Р╨Ь╨Х╨в╨а╨Ш╨Ч╨Ю╨Т╨Р╨Э╨Э╨л╨Щ ╨Ч╨Р╨Я╨а╨Ю╨б - ╨╖╨░╤Й╨╕╤В╨░ ╨╛╤В SQL-╨╕╨╜╤К╨╡╨║╤Ж╨╕╨╣
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    print(f"ЁЯЫбя╕П ╨Т╨л╨Я╨Ю╨Ы╨Э╨п╨Х╨в╨б╨п ╨С╨Х╨Ч╨Ю╨Я╨Р╨б╨Э╨л╨Щ SQL: {query} ╤Б ╨┐╨░╤А╨░╨╝╨╡╤В╤А╨░╨╝╨╕: ({username}, {password})")
    
    try:
        start_time = time.time()
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        execution_time = time.time() - start_time
        
        conn.close()
        
        if user:
            print(f"тЬЕ ╨г╨б╨Я╨Х╨е: ╨Э╨░╨╣╨┤╨╡╨╜ ╨┐╨╛╨╗╤М╨╖╨╛╨▓╨░╤В╨╡╨╗╤М: {user}")
            return user
        else:
            print("тЭМ ╨Э╨╡ ╨╜╨░╨╣╨┤╨╡╨╜ ╨┐╨╛╨╗╤М╨╖╨╛╨▓╨░╤В╨╡╨╗╤М")
            return None
            
    except Exception as e:
        print(f"ЁЯТе ╨Ю╨и╨Ш╨С╨Ъ╨Р SQL: {e}")
        conn.close()
        return None

def safe_register(username, password):
    """╨С╨Х╨Ч╨Ю╨Я╨Р╨б╨Э╨Р╨п ╤А╨╡╨│╨╕╤Б╤В╤А╨░╤Ж╨╕╤П ╤Б ╨┐╨░╤А╨░╨╝╨╡╤В╤А╨╕╨╖╨╛╨▓╨░╨╜╨╜╤Л╨╝╨╕ ╨╖╨░╨┐╤А╨╛╤Б╨░╨╝╨╕"""
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    
    try:
        # ╨Я╨Р╨а╨Р╨Ь╨Х╨в╨а╨Ш╨Ч╨Ю╨Т╨Р╨Э╨Э╨л╨Щ ╨Ч╨Р╨Я╨а╨Ю╨б
        query = "INSERT INTO users (username, password) VALUES (?, ?)"
        print(f"ЁЯЫбя╕П ╨Т╨л╨Я╨Ю╨Ы╨Э╨п╨Х╨в╨б╨п ╨С╨Х╨Ч╨Ю╨Я╨Р╨б╨Э╨л╨Щ SQL: {query} ╤Б ╨┐╨░╤А╨░╨╝╨╡╤В╤А╨░╨╝╨╕: ({username}, {password})")
        
        cursor.execute(query, (username, password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        print("ЁЯТе ╨Ю╤И╨╕╨▒╨║╨░: ╨┐╨╛╨╗╤М╨╖╨╛╨▓╨░╤В╨╡╨╗╤М ╤Г╨╢╨╡ ╤Б╤Г╤Й╨╡╤Б╤В╨▓╤Г╨╡╤В")
        conn.close()
        return False
    except Exception as e:
        print(f"ЁЯТе ╨Ю╤И╨╕╨▒╨║╨░ ╤А╨╡╨│╨╕╤Б╤В╤А╨░╤Ж╨╕╨╕: {e}")
        conn.close()
        return False

def safe_get_user_by_id(user_id):
    """╨С╨Х╨Ч╨Ю╨Я╨Р╨б╨Э╨Ю╨Х ╨┐╨╛╨╗╤Г╤З╨╡╨╜╨╕╨╡ ╨┐╨╛╨╗╤М╨╖╨╛╨▓╨░╤В╨╡╨╗╤П ╨┐╨╛ ID"""
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    
    # ╨Я╨Р╨а╨Р╨Ь╨Х╨в╨а╨Ш╨Ч╨Ю╨Т╨Р╨Э╨Э╨л╨Щ ╨Ч╨Р╨Я╨а╨Ю╨б
    query = "SELECT * FROM users WHERE id = ?"
    print(f"ЁЯЫбя╕П ╨Т╨л╨Я╨Ю╨Ы╨Э╨п╨Х╨в╨б╨п ╨С╨Х╨Ч╨Ю╨Я╨Р╨б╨Э╨л╨Щ SQL: {query} ╤Б ╨┐╨░╤А╨░╨╝╨╡╤В╤А╨╛╨╝: {user_id}")
    
    try:
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        print(f"ЁЯТе ╨Ю╤И╨╕╨▒╨║╨░: {e}")
        conn.close()
        return None

def safe_get_user_by_username(username):
    """╨С╨Х╨Ч╨Ю╨Я╨Р╨б╨Э╨Ю╨Х ╨┐╨╛╨╗╤Г╤З╨╡╨╜╨╕╨╡ ╨┐╨╛╨╗╤М╨╖╨╛╨▓╨░╤В╨╡╨╗╤П ╨┐╨╛ ╨╕╨╝╨╡╨╜╨╕"""
    conn = sqlite3.connect('notes.db')
    cursor = conn.cursor()
    
    # ╨Я╨Р╨а╨Р╨Ь╨Х╨в╨а╨Ш╨Ч╨Ю╨Т╨Р╨Э╨Э╨л╨Щ ╨Ч╨Р╨Я╨а╨Ю╨б
    query = "SELECT * FROM users WHERE username = ?"
    print(f"ЁЯЫбя╕П ╨Т╨л╨Я╨Ю╨Ы╨Э╨п╨Х╨в╨б╨п ╨С╨Х╨Ч╨Ю╨Я╨Р╨б╨Э╨л╨Щ SQL: {query} ╤Б ╨┐╨░╤А╨░╨╝╨╡╤В╤А╨╛╨╝: {username}")
    
    try:
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        print(f"ЁЯТе ╨Ю╤И╨╕╨▒╨║╨░: {e}")
        conn.close()
        return None

# -------------------------------
# ╨Ю╨▒╤А╨░╨▒╨╛╤В╤З╨╕╨║╨╕ ╨╛╤И╨╕╨▒╨╛╨║
# -------------------------------
@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error_500.html', error=str(error)), 500

@app.errorhandler(Exception)
def handle_all_exceptions(error):
    return render_template('error_500.html', error="Internal Server Error"), 500

# -------------------------------
# ╨Ь╨░╤А╤И╤А╤Г╤В╤Л ╨░╤Г╤В╨╡╨╜╤В╨╕╤Д╨╕╨║╨░╤Ж╨╕╨╕ (╨С╨Х╨Ч╨Ю╨Я╨Р╨б╨Э╨л╨Х)
# -------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        print(f"ЁЯФР ╨Я╨╛╨┐╤Л╤В╨║╨░ ╨▓╤Е╨╛╨┤╨░: username='{username}', password='{password}'")
        
        # ╨Т╨░╨╗╨╕╨┤╨░╤Ж╨╕╤П ╨▓╤Е╨╛╨┤╨╜╤Л╤Е ╨┤╨░╨╜╨╜╤Л╤Е
        if not username or not password:
            flash('╨Ч╨░╨┐╨╛╨╗╨╜╨╕╤В╨╡ ╨▓╤Б╨╡ ╨┐╨╛╨╗╤П!', 'error')
            return render_template('login.html')
        
        # ╨Я╤А╨╛╨▓╨╡╤А╨║╨░ ╨╜╨░ ╤Б╨╗╨╕╤И╨║╨╛╨╝ ╨┤╨╗╨╕╨╜╨╜╤Л╨╡ ╨▓╤Е╨╛╨┤╨╜╤Л╨╡ ╨┤╨░╨╜╨╜╤Л╨╡ (╨┤╨╛╨┐╨╛╨╗╨╜╨╕╤В╨╡╨╗╤М╨╜╨░╤П ╨╖╨░╤Й╨╕╤В╨░)
        if len(username) > 50 or len(password) > 50:
            flash('╨б╨╗╨╕╤И╨║╨╛╨╝ ╨┤╨╗╨╕╨╜╨╜╤Л╨╡ ╨┤╨░╨╜╨╜╤Л╨╡!', 'error')
            return render_template('login.html')
        
        user = safe_login(username, password)
        
        if user:
            if len(user) == 4:
                user_id, username, password, created_at = user
            elif len(user) == 3:
                user_id, username, password = user
                created_at = None
            else:
                flash('╨Ю╤И╨╕╨▒╨║╨░ ╨┤╨░╨╜╨╜╤Л╤Е ╨┐╨╛╨╗╤М╨╖╨╛╨▓╨░╤В╨╡╨╗╤П', 'error')
                return render_template('login.html')
            
            session['user_id'] = str(user_id)
            session['username'] = username
            flash(f'╨г╤Б╨┐╨╡╤И╨╜╤Л╨╣ ╨▓╤Е╨╛╨┤ ╨║╨░╨║ {username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('╨Э╨╡╨▓╨╡╤А╨╜╤Л╨╡ ╤Г╤З╨╡╤В╨╜╤Л╨╡ ╨┤╨░╨╜╨╜╤Л╨╡!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # ╨Т╨░╨╗╨╕╨┤╨░╤Ж╨╕╤П ╨▓╤Е╨╛╨┤╨╜╤Л╤Е ╨┤╨░╨╜╨╜╤Л╤Е
        if not username or not password:
            flash('╨Ч╨░╨┐╨╛╨╗╨╜╨╕╤В╨╡ ╨▓╤Б╨╡ ╨┐╨╛╨╗╤П!', 'error')
            return render_template('register.html')
        
        if len(username) < 3 or len(password) < 3:
            flash('╨Ы╨╛╨│╨╕╨╜ ╨╕ ╨┐╨░╤А╨╛╨╗╤М ╨┤╨╛╨╗╨╢╨╜╤Л ╨▒╤Л╤В╤М ╨╜╨╡ ╨╝╨╡╨╜╨╡╨╡ 3 ╤Б╨╕╨╝╨▓╨╛╨╗╨╛╨▓!', 'error')
            return render_template('register.html')
        
        if len(username) > 50 or len(password) > 50:
            flash('╨б╨╗╨╕╤И╨║╨╛╨╝ ╨┤╨╗╨╕╨╜╨╜╤Л╨╡ ╨┤╨░╨╜╨╜╤Л╨╡!', 'error')
            return render_template('register.html')
        
        if safe_register(username, password):
            flash('╨а╨╡╨│╨╕╤Б╤В╤А╨░╤Ж╨╕╤П ╤Г╤Б╨┐╨╡╤И╨╜╨░! ╨в╨╡╨┐╨╡╤А╤М ╨╝╨╛╨╢╨╡╤В╨╡ ╨▓╨╛╨╣╤В╨╕.', 'success')
            return redirect(url_for('login'))
        else:
            flash('╨Ю╤И╨╕╨▒╨║╨░ ╤А╨╡╨│╨╕╤Б╤В╤А╨░╤Ж╨╕╨╕. ╨Т╨╛╨╖╨╝╨╛╨╢╨╜╨╛, ╨┐╨╛╨╗╤М╨╖╨╛╨▓╨░╤В╨╡╨╗╤М ╤Г╨╢╨╡ ╤Б╤Г╤Й╨╡╤Б╤В╨▓╤Г╨╡╤В.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('╨Т╤Л ╨▓╤Л╤И╨╗╨╕ ╨╕╨╖ ╤Б╨╕╤Б╤В╨╡╨╝╤Л.', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('╨б╨╜╨░╤З╨░╨╗╨░ ╨▓╨╛╨╣╨┤╨╕╤В╨╡ ╨▓ ╤Б╨╕╤Б╤В╨╡╨╝╤Г.', 'error')
        return redirect(url_for('login'))
    
    user = safe_get_user_by_id(session['user_id'])
    
    if user:
        if len(user) >= 4:
            user_id, username, password, created_at = user
        elif len(user) >= 3:
            user_id, username, password = user
            created_at = None
        else:
            flash('╨Э╨╡╨▓╨╡╤А╨╜╨░╤П ╤Б╤В╤А╤Г╨║╤В╤Г╤А╨░ ╨┐╨╛╨╗╤М╨╖╨╛╨▓╨░╤В╨╡╨╗╤П', 'error')
            return redirect(url_for('index'))
            
        return render_template('profile.html', 
                             username=username, 
                             password=password,
                             created_at=created_at)
    else:
        flash('╨Я╨╛╨╗╤М╨╖╨╛╨▓╨░╤В╨╡╨╗╤М ╨╜╨╡ ╨╜╨░╨╣╨┤╨╡╨╜.', 'error')
        return redirect(url_for('index'))

# -------------------------------
# ╨Ю╤Б╤В╨░╨╗╤М╨╜╤Л╨╡ ╤Д╤Г╨╜╨║╤Ж╨╕╨╕ ╨╕ ╨╝╨░╤А╤И╤А╤Г╤В╤Л
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
                flash('╨Ч╨░╨╝╨╡╤В╨║╨░ ╤Г╤Б╨┐╨╡╤И╨╜╨╛ ╤Б╨╛╨╖╨┤╨░╨╜╨░!', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                flash('╨Я╤А╨╛╨╕╨╖╨╛╤И╨╗╨░ ╨╛╤И╨╕╨▒╨║╨░ ╨┐╤А╨╕ ╤Б╨╛╨╖╨┤╨░╨╜╨╕╨╕ ╨╖╨░╨╝╨╡╤В╨║╨╕', 'error')

    user_id = get_or_create_user_id()
    notes = get_user_notes(user_id)
    username = session.get('username', '╨У╨╛╤Б╤В╤М')
    
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
        flash('╨Ч╨░╨╝╨╡╤В╨║╨░ ╨╜╨╡ ╨╜╨░╨╣╨┤╨╡╨╜╨░', 'error')
        return redirect(url_for('index'))
    
    note_id, title, content, user_id, created_at = note_data
    
    if not can_edit_note(user_id):
        flash('╨г ╨▓╨░╤Б ╨╜╨╡╤В ╨┐╤А╨░╨▓ ╨┤╨╗╤П ╤А╨╡╨┤╨░╨║╤В╨╕╤А╨╛╨▓╨░╨╜╨╕╤П ╤Н╤В╨╛╨╣ ╨╖╨░╨╝╨╡╤В╨║╨╕', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        new_title = request.form.get('title', '')
        new_content = request.form.get('content', '')
        
        if new_title and new_content:
            try:
                update_note(note_id, new_title, new_content)
                flash('╨Ч╨░╨╝╨╡╤В╨║╨░ ╤Г╤Б╨┐╨╡╤И╨╜╨╛ ╨╛╨▒╨╜╨╛╨▓╨╗╨╡╨╜╨░!', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                flash('╨Я╤А╨╛╨╕╨╖╨╛╤И╨╗╨░ ╨╛╤И╨╕╨▒╨║╨░ ╨┐╤А╨╕ ╨╛╨▒╨╜╨╛╨▓╨╗╨╡╨╜╨╕╨╕ ╨╖╨░╨╝╨╡╤В╨║╨╕', 'error')

    return render_template('edit.html', note={'id': note_id, 'title': title, 'content': content})

@app.route('/delete/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    note_data = get_note(note_id)
    if not note_data:
        flash('╨Ч╨░╨╝╨╡╤В╨║╨░ ╨╜╨╡ ╨╜╨░╨╣╨┤╨╡╨╜╨░', 'error')
        return redirect(url_for('index'))
    
    note_id, title, content, user_id, created_at = note_data
    
    if not can_edit_note(user_id):
        flash('╨г ╨▓╨░╤Б ╨╜╨╡╤В ╨┐╤А╨░╨▓ ╨┤╨╗╤П ╤Г╨┤╨░╨╗╨╡╨╜╨╕╤П ╤Н╤В╨╛╨╣ ╨╖╨░╨╝╨╡╤В╨║╨╕', 'error')
        return redirect(url_for('index'))

    try:
        delete_note(note_id)
        flash('╨Ч╨░╨╝╨╡╤В╨║╨░ ╤Г╤Б╨┐╨╡╤И╨╜╨╛ ╤Г╨┤╨░╨╗╨╡╨╜╨░!', 'success')
    except Exception as e:
        flash('╨Я╤А╨╛╨╕╨╖╨╛╤И╨╗╨░ ╨╛╤И╨╕╨▒╨║╨░ ╨┐╤А╨╕ ╤Г╨┤╨░╨╗╨╡╨╜╨╕╨╕ ╨╖╨░╨╝╨╡╤В╨║╨╕', 'error')

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
    
    username = session.get('username', '╨У╨╛╤Б╤В╤М')
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
    flash('╨б╨╡╤Б╤Б╨╕╤П ╨╛╤З╨╕╤Й╨╡╨╜╨░. ╨Т╤Л ╤В╨╡╨┐╨╡╤А╤М ╨╜╨╛╨▓╤Л╨╣ ╨┐╨╛╨╗╤М╨╖╨╛╨▓╨░╤В╨╡╨╗╤М.', 'success')
    return redirect(url_for('index'))

def create_ssl_context():
    """╨б╨╛╨╖╨┤╨░╨╜╨╕╨╡ SSL ╨║╨╛╨╜╤В╨╡╨║╤Б╤В╨░ ╤Б ╤Б╨░╨╝╨╛╨┐╨╛╨┤╨┐╨╕╤Б╨░╨╜╨╜╤Л╨╝╨╕ ╤Б╨╡╤А╤В╨╕╤Д╨╕╨║╨░╤В╨░╨╝╨╕"""
    try:
        # ╨Я╤А╨╛╨▓╨╡╤А╤П╨╡╨╝ ╤Б╤Г╤Й╨╡╤Б╤В╨▓╨╛╨▓╨░╨╜╨╕╨╡ ╤Б╨╡╤А╤В╨╕╤Д╨╕╨║╨░╤В╨╛╨▓
        if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
            print("тЪая╕П SSL ╤Б╨╡╤А╤В╨╕╤Д╨╕╨║╨░╤В╤Л ╨╜╨╡ ╨╜╨░╨╣╨┤╨╡╨╜╤Л. ╨б╨╛╨╖╨┤╨░╨╡╨╝ ╤Б╨░╨╝╨╛╨┐╨╛╨┤╨┐╨╕╤Б╨░╨╜╨╜╤Л╨╡...")
            create_self_signed_cert()
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('cert.pem', 'key.pem')
        print("тЬЕ SSL ╨║╨╛╨╜╤В╨╡╨║╤Б╤В ╤Б╨╛╨╖╨┤╨░╨╜ ╤Г╤Б╨┐╨╡╤И╨╜╨╛")
        return context
    except Exception as e:
        print(f"тЭМ ╨Ю╤И╨╕╨▒╨║╨░ ╤Б╨╛╨╖╨┤╨░╨╜╨╕╤П SSL ╨║╨╛╨╜╤В╨╡╨║╤Б╤В╨░: {e}")
        return None

def create_self_signed_cert():
    """╨б╨╛╨╖╨┤╨░╨╜╨╕╨╡ ╤Б╨░╨╝╨╛╨┐╨╛╨┤╨┐╨╕╤Б╨░╨╜╨╜╤Л╤Е SSL ╤Б╨╡╤А╤В╨╕╤Д╨╕╨║╨░╤В╨╛╨▓"""
    try:
        import subprocess
        import sys
        
        # ╨б╨╛╨╖╨┤╨░╨╜╨╕╨╡ ╨┐╤А╨╕╨▓╨░╤В╨╜╨╛╨│╨╛ ╨║╨╗╤О╤З╨░
        result = subprocess.run([
            'openssl', 'genrsa', '-out', 'key.pem', '2048'
        ], capture_output=True, text=True, check=False)
        
        if result.returncode != 0:
            print(f"тЭМ ╨Ю╤И╨╕╨▒╨║╨░ ╤Б╨╛╨╖╨┤╨░╨╜╨╕╤П ╨║╨╗╤О╤З╨░: {result.stderr}")
            return False
        
        # ╨б╨╛╨╖╨┤╨░╨╜╨╕╨╡ ╤Б╨░╨╝╨╛╨┐╨╛╨┤╨┐╨╕╤Б╨░╨╜╨╜╨╛╨│╨╛ ╤Б╨╡╤А╤В╨╕╤Д╨╕╨║╨░╤В╨░
        result = subprocess.run([
            'openssl', 'req', '-new', '-x509', '-key', 'key.pem', 
            '-out', 'cert.pem', '-days', '365', 
            '-subj', '/C=US/ST=California/L=San Francisco/O=My Company/CN=localhost'
        ], capture_output=True, text=True, check=False)
        
        if result.returncode == 0:
            print("тЬЕ ╨б╨░╨╝╨╛╨┐╨╛╨┤╨┐╨╕╤Б╨░╨╜╨╜╤Л╨╡ SSL ╤Б╨╡╤А╤В╨╕╤Д╨╕╨║╨░╤В╤Л ╤Б╨╛╨╖╨┤╨░╨╜╤Л ╤З╨╡╤А╨╡╨╖ OpenSSL")
            return True
        else:
            print(f"тЭМ ╨Ю╤И╨╕╨▒╨║╨░ ╤Б╨╛╨╖╨┤╨░╨╜╨╕╤П ╤Б╨╡╤А╤В╨╕╤Д╨╕╨║╨░╤В╨░: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"тЭМ ╨Э╨╡ ╤Г╨┤╨░╨╗╨╛╤Б╤М ╤Б╨╛╨╖╨┤╨░╤В╤М SSL ╤Б╨╡╤А╤В╨╕╤Д╨╕╨║╨░╤В╤Л ╤З╨╡╤А╨╡╨╖ OpenSSL: {e}")
        print("ЁЯУЭ ╨г╤Б╤В╨░╨╜╨╛╨▓╨╕╤В╨╡ OpenSSL ╨╕╨╗╨╕ ╨╕╤Б╨┐╨╛╨╗╤М╨╖╤Г╨╣╤В╨╡ ╤А╨╡╨╢╨╕╨╝ HTTP")
        return False

def run_with_waitress_http():
    """╨Ч╨░╨┐╤Г╤Б╨║ ╨┐╤А╨╕╨╗╨╛╨╢╨╡╨╜╨╕╤П ╤З╨╡╤А╨╡╨╖ Waitress ╤Б HTTP"""
    print("ЁЯЪА ╨Ч╨░╨┐╤Г╤Б╨║ Waitress ╤Б HTTP...")
    print("ЁЯУЭ ╨Я╤А╨╕╨╗╨╛╨╢╨╡╨╜╨╕╨╡ ╨┤╨╛╤Б╤В╤Г╨┐╨╜╨╛ ╨┐╨╛ ╨░╨┤╤А╨╡╤Б╤Г: http://localhost:8080")
    serve(
        app,
        host='0.0.0.0',
        port=8080,
        threads=4
    )

def run_with_flask_https():
    """╨Ч╨░╨┐╤Г╤Б╨║ ╨┐╤А╨╕╨╗╨╛╨╢╨╡╨╜╨╕╤П ╤З╨╡╤А╨╡╨╖ Flask ╤Б HTTPS"""
    print("ЁЯЪА ╨Ч╨░╨┐╤Г╤Б╨║ Flask ╤Б HTTPS...")
    ssl_context = create_ssl_context()
    if ssl_context:
        print("ЁЯУЭ ╨Я╤А╨╕╨╗╨╛╨╢╨╡╨╜╨╕╨╡ ╨┤╨╛╤Б╤В╤Г╨┐╨╜╨╛ ╨┐╨╛ ╨░╨┤╤А╨╡╤Б╤Г: https://localhost:8443")
        app.run(host='0.0.0.0', port=8443, ssl_context=ssl_context, debug=False)
    else:
        print("тЭМ ╨Э╨╡ ╤Г╨┤╨░╨╗╨╛╤Б╤М ╨╖╨░╨┐╤Г╤Б╤В╨╕╤В╤М ╤Б HTTPS. ╨Ч╨░╨┐╤Г╤Б╨║╨░╨╡╨╝ ╤Б HTTP...")
        run_with_flask_http()

def run_with_flask_http():
    """╨Ч╨░╨┐╤Г╤Б╨║ ╨┐╤А╨╕╨╗╨╛╨╢╨╡╨╜╨╕╤П ╤З╨╡╤А╨╡╨╖ Flask ╤Б HTTP"""
    print("ЁЯЪА ╨Ч╨░╨┐╤Г╤Б╨║ Flask ╤Б HTTP...")
    print("ЁЯУЭ ╨Я╤А╨╕╨╗╨╛╨╢╨╡╨╜╨╕╨╡ ╨┤╨╛╤Б╤В╤Г╨┐╨╜╨╛ ╨┐╨╛ ╨░╨┤╤А╨╡╤Б╤Г: http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)

def run_with_nginx_proxy():
    """╨а╨╡╨║╨╛╨╝╨╡╨╜╨┤╤Г╨╡╨╝╤Л╨╣ ╤Б╨┐╨╛╤Б╨╛╨▒: Waitress + nginx reverse proxy"""
    print("ЁЯЪА ╨Ч╨░╨┐╤Г╤Б╨║ Waitress (╨┤╨╗╤П ╨╕╤Б╨┐╨╛╨╗╤М╨╖╨╛╨▓╨░╨╜╨╕╤П ╤Б nginx)...")
    print("ЁЯУЭ ╨Я╤А╨╕╨╗╨╛╨╢╨╡╨╜╨╕╨╡ ╨┤╨╛╤Б╤В╤Г╨┐╨╜╨╛ ╨┐╨╛ ╨░╨┤╤А╨╡╤Б╤Г: http://localhost:8080")
    print("ЁЯТб ╨Ф╨╗╤П HTTPS ╨╜╨░╤Б╤В╤А╨╛╨╣╤В╨╡ nginx ╨║╨░╨║ reverse proxy")
    serve(
        app,
        host='0.0.0.0',
        port=8080,
        threads=4
    )

if __name__ == '__main__':
    print("=" * 50)
    print("ЁЯФз ╨Т╤Л╨▒╨╡╤А╨╕╤В╨╡ ╤А╨╡╨╢╨╕╨╝ ╨╖╨░╨┐╤Г╤Б╨║╨░:")
    print("1. Waitress + HTTP (╤А╨╡╨║╨╛╨╝╨╡╨╜╨┤╤Г╨╡╤В╤Б╤П ╨┤╨╗╤П ╨┐╤А╨╛╨┤╨░╨║╤И╨╡╨╜╨░)")
    print("2. Flask + HTTPS (╨┤╨╗╤П ╤А╨░╨╖╤А╨░╨▒╨╛╤В╨║╨╕)")
    print("3. Flask + HTTP (╨┤╨╗╤П ╤А╨░╨╖╤А╨░╨▒╨╛╤В╨║╨╕)")
    print("4. Waitress ╨┤╨╗╤П nginx (reverse proxy)")
    print("=" * 50)
    
    try:
        choice = input("╨Т╨▓╨╡╨┤╨╕╤В╨╡ ╨╜╨╛╨╝╨╡╤А (1-4, ╨┐╨╛ ╤Г╨╝╨╛╨╗╤З╨░╨╜╨╕╤О 1): ").strip()
    except:
        choice = "1"
    
    if choice == "2":
        run_with_flask_https()
    elif choice == "3":
        run_with_flask_http()
    elif choice == "4":
        run_with_nginx_proxy()
    else:
        # ╨Я╨╛ ╤Г╨╝╨╛╨╗╤З╨░╨╜╨╕╤О Waitress + HTTP
        run_with_waitress_http()



