from app import app, init_db, start_tcp_server, HTTP_PORT

if __name__ == "__main__":
    init_db()
    start_tcp_server()
    app.run(host="127.0.0.1", port=HTTP_PORT, debug=True)
