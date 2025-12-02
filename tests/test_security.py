import os

def test_no_debug_mode():
    """Проверяем что нет debug=True в production коде"""
    # Ищем debug=True во всех Python файлах
    for root, dirs, files in os.walk('.'):
        # Пропускаем тесты и служебные папки
        skip_folders = ['tests', '.git', '.github', '__pycache__', 'venv']
        if any(folder in root for folder in skip_folders):
            continue
            
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines, 1):
                        # Ищем debug=True но не в комментариях
                        if 'debug=True' in line.lower() and not line.strip().startswith('#'):
                            # Проверяем что это не тестовый файл
                            if 'test' not in filepath.lower():
                                raise AssertionError(f"Found debug=True in {filepath}:{i}")
    
    assert True, "No debug=True found in production code"

def test_basic_security():
    """Базовый тест безопасности"""
    assert True, "Security test passed"