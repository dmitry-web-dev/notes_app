from app import app

if __name__ == '__main__':
    from waitress import serve
    print("Production сервер запущен: http://127.0.0.1:5000")
    print("Server header полностью скрыт")
    serve(app, host='127.0.0.1', port=5000, ident=None)