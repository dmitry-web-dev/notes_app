#!/usr/bin/env python3
"""
Production server setup for Flask application
Usage: python run_production.py
"""

import os
import sys
from waitress import serve
import logging
from app import create_production_app

# Настройка логирования для продакшн
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/flask_app/app.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('waitress')

def run_production():
    """Запуск приложения в продакшн режиме"""
    
    app = create_production_app()
    
    # Конфигурация Waitress для продакшн
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', '8080'))
    
    logger.info(f"🚀 Starting production server on {host}:{port}")
    logger.info("📝 Application will be served behind nginx")
    logger.info("🔒 HTTPS will be handled by nginx")
    
    # Waitress конфигурация для продакшн
    serve(
        app,
        host=host,
        port=port,
        threads=8,  # Количество потоков
        channel_timeout=60,  # Таймаут канала
        connection_limit=1000,  # Лимит соединений
        asyncore_use_poll=True,  # Использовать poll для лучшей производительности
        url_prefix='',  # Префикс URL (если нужно)
        ident='Flask App Server'  # Идентификатор сервера
    )

if __name__ == '__main__':
    run_production()