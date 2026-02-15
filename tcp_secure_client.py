from __future__ import annotations

import json
import socket

HOST = "127.0.0.1"
PORT = 5095


def main() -> None:
    payload = {
        "sender": "nodo-tcp-a",
        "receiver": "nodo-tcp-b",
        "key_name": "default_xor",
        "message": "Hola desde cliente TCP protegido",
    }

    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        sock.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        response = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        print("Respuesta:", response)


if __name__ == "__main__":
    main()
