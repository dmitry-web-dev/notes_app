import os
import sys
from dotenv import load_dotenv

def security_check():
    """Проверка критических настроек безопасности"""
    load_dotenv()
    
    issues = []
    warnings = []
    
    # Проверка секретного ключа
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        issues.append(" SECRET_KEY не установлен в переменных окружения")
    elif 'dev-secret-key' in secret_key or 'change-in-production' in secret_key:
        issues.append("Используется дефолтный или слабый SECRET_KEY")
    elif len(secret_key) < 32:
        warnings.append("SECRET_KEY рекомендуется длиной не менее 32 символов")
    else:
        issues.append("SECRET_KEY настроен правильно")
    
    # Проверка режима отладки
    flask_env = os.environ.get('FLASK_ENV', 'development')
    if flask_env == 'production':
        if os.environ.get('DEBUG'):
            issues.append(" DEBUG включен в production среде")
        else:
            issues.append(" Production режим настроен правильно")
    else:
        warnings.append("  Запуск в development режиме")
    
    return issues, warnings

if __name__ == '__main__':
    print("ПРОВЕРКА БЕЗОПАСНОСТИ ПРИЛОЖЕНИЯ")
    print("=" * 50)
    
    issues, warnings = security_check()
    
    if issues:
        print("\nКРИТИЧЕСКИЕ ПРОБЛЕМЫ:")
        for issue in issues:
            print(f"  {issue}")
    
    if warnings:
        print("\nПРЕДУПРЕЖДЕНИЯ:")
        for warning in warnings:
            print(f"  {warning}")
    
    if not issues and not warnings:
        print("\nВсе проверки пройдены! Приложение безопасно.")
    elif any("❌" in issue for issue in issues):
        print(f"\nОбнаружены критические проблемы: {len([i for i in issues if '❌' in i])}")
        sys.exit(1)
    else:
        print("\nЕсть предупреждения, но приложение может быть запущено")

    