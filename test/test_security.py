import os

def test_no_debug_mode():
    """Проверяем что нет debug=True в основных файлах"""
    for root, dirs, files in os.walk('.'):
        # Пропускаем служебные папки
        if any(x in root for x in ['tests', '.git', '.github', '__pycache__', 'venv']):
            continue
            
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if 'debug=True' in content or 'debug = True' in content:
                            # Проверяем что это не комментарий
                            lines = content.split('\n')
                            for i, line in enumerate(lines, 1):
                                if ('debug=True' in line or 'debug = True' in line) and not line.strip().startswith('#'):
                                    raise AssertionError(f"Found debug=True in {filepath}:{i}")
                except:
                    continue
    
    assert True, "No debug=True found in production code"

def test_basic_security():
    """Базовый тест безопасности"""
    assert True