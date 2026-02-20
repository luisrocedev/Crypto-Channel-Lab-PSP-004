from __future__ import annotations

import base64
import json
import os
import socketserver
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "secure_channel.sqlite3"
HTTP_PORT = int(os.getenv("CRYPTO_HTTP_PORT", "5080"))
TCP_PORT = int(os.getenv("CRYPTO_TCP_PORT", "5095"))

app = Flask(__name__)

state_lock = threading.Lock()
state: dict[str, Any] = {
    "http_messages": 0,
    "tcp_messages": 0,
    "decrypt_ops": 0,
}


class CaesarCipher:
    def __init__(self, shift: int) -> None:
        self.shift = shift

    def encrypt(self, text: str) -> str:
        out = []
        for ch in text:
            out.append(chr((ord(ch) + self.shift) % 65536))
        return "".join(out)

    def decrypt(self, text: str) -> str:
        out = []
        for ch in text:
            out.append(chr((ord(ch) - self.shift) % 65536))
        return "".join(out)


class XorCipher:
    def __init__(self, secret: str) -> None:
        self.secret_bytes = secret.encode("utf-8")

    def _xor(self, data: bytes) -> bytes:
        key = self.secret_bytes
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    def encrypt(self, text: str) -> str:
        raw = text.encode("utf-8")
        xored = self._xor(raw)
        return base64.b64encode(xored).decode("utf-8")

    def decrypt(self, text: str) -> str:
        raw = base64.b64decode(text.encode("utf-8"))
        plain = self._xor(raw)
        return plain.decode("utf-8", errors="ignore")


@dataclass
class KeyConfig:
    name: str
    cipher: str
    secret: str
    shift: int


class CipherFactory:
    @staticmethod
    def from_key(config: KeyConfig):
        if config.cipher == "caesar":
            return CaesarCipher(config.shift)
        return XorCipher(config.secret)


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def init_db() -> None:
    conn = db_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS keys_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            cipher TEXT NOT NULL,
            secret TEXT NOT NULL,
            shift INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            channel TEXT NOT NULL,
            key_name TEXT NOT NULL,
            cipher TEXT NOT NULL,
            encrypted_payload TEXT NOT NULL,
            plain_preview TEXT NOT NULL,
            status TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS decrypt_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            result_preview TEXT NOT NULL,
            FOREIGN KEY(message_id) REFERENCES messages(id)
        );

        CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
        """
    )

    existing = conn.execute("SELECT COUNT(*) AS c FROM keys_store").fetchone()["c"]
    if existing == 0:
        conn.execute(
            """
            INSERT INTO keys_store (name, cipher, secret, shift, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("default_caesar", "caesar", "", 5, now_text()),
        )
        conn.execute(
            """
            INSERT INTO keys_store (name, cipher, secret, shift, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("default_xor", "xor", "DAM2-PSP", 0, now_text()),
        )

    conn.commit()
    conn.close()


def load_key(name: str) -> KeyConfig | None:
    conn = db_conn()
    row = conn.execute(
        "SELECT name, cipher, secret, shift FROM keys_store WHERE name = ?",
        (name,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return KeyConfig(
        name=row["name"],
        cipher=row["cipher"],
        secret=row["secret"],
        shift=int(row["shift"]),
    )


def save_message(
    sender: str,
    receiver: str,
    channel: str,
    key_name: str,
    cipher: str,
    encrypted_payload: str,
    plain_preview: str,
    status: str,
) -> int:
    conn = db_conn()
    cur = conn.execute(
        """
        INSERT INTO messages (
            created_at, sender, receiver, channel, key_name, cipher,
            encrypted_payload, plain_preview, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            now_text(),
            sender,
            receiver,
            channel,
            key_name,
            cipher,
            encrypted_payload,
            plain_preview,
            status,
        ),
    )
    conn.commit()
    message_id = int(cur.lastrowid)
    conn.close()
    return message_id


def encrypt_with_key(key_name: str, plain_text: str) -> tuple[str, str] | None:
    key_cfg = load_key(key_name)
    if key_cfg is None:
        return None
    cipher = CipherFactory.from_key(key_cfg)
    encrypted = cipher.encrypt(plain_text)
    return key_cfg.cipher, encrypted


def decrypt_with_key(key_name: str, encrypted_text: str) -> str | None:
    key_cfg = load_key(key_name)
    if key_cfg is None:
        return None
    cipher = CipherFactory.from_key(key_cfg)
    return cipher.decrypt(encrypted_text)


class SecureTCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            raw = self.rfile.readline()
            if not raw:
                break

            try:
                data = json.loads(raw.decode("utf-8", errors="ignore"))
            except json.JSONDecodeError:
                self.wfile.write(b'{"ok":false,"error":"invalid_json"}\\n')
                continue

            sender = str(data.get("sender", self.client_address[0]))[:80]
            receiver = str(data.get("receiver", "server"))[:80]
            key_name = str(data.get("key_name", "default_caesar"))[:80]
            plain_text = str(data.get("message", ""))[:600]

            encrypted_result = encrypt_with_key(key_name, plain_text)
            if encrypted_result is None:
                self.wfile.write(b'{"ok":false,"error":"unknown_key"}\\n')
                continue

            cipher_name, encrypted_payload = encrypted_result
            message_id = save_message(
                sender=sender,
                receiver=receiver,
                channel="tcp",
                key_name=key_name,
                cipher=cipher_name,
                encrypted_payload=encrypted_payload,
                plain_preview=plain_text[:140],
                status="encrypted",
            )

            with state_lock:
                state["tcp_messages"] += 1

            response = json.dumps({"ok": True, "message_id": message_id}, ensure_ascii=False)
            self.wfile.write((response + "\\n").encode("utf-8"))


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_tcp_server() -> None:
    def run() -> None:
        try:
            with ThreadedTCPServer(("0.0.0.0", TCP_PORT), SecureTCPHandler) as server:
                server.serve_forever()
        except OSError as exc:
            print(f"[TCP] No se pudo iniciar en :{TCP_PORT} — {exc}")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()


@app.get("/")
def index() -> str:
    return render_template("index.html", tcp_port=TCP_PORT)


@app.get("/api/keys")
def get_keys():
    conn = db_conn()
    rows = conn.execute(
        """
        SELECT id, name, cipher, shift, created_at
        FROM keys_store
        ORDER BY id DESC
        """
    ).fetchall()
    conn.close()
    return jsonify({"ok": True, "items": [dict(r) for r in rows]})


@app.post("/api/keys")
def create_key():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()[:80]
    cipher = str(payload.get("cipher", "caesar")).strip().lower()

    if not name:
        return jsonify({"ok": False, "error": "name_required"}), 400
    if cipher not in ("caesar", "xor"):
        return jsonify({"ok": False, "error": "cipher_invalid"}), 400

    if cipher == "caesar":
        shift = int(payload.get("shift", 5))
        secret = ""
    else:
        shift = 0
        secret = str(payload.get("secret", "")).strip()
        if not secret:
            return jsonify({"ok": False, "error": "secret_required"}), 400

    try:
        conn = db_conn()
        conn.execute(
            """
            INSERT INTO keys_store (name, cipher, secret, shift, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name, cipher, secret, shift, now_text()),
        )
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "name_exists"}), 409

    return jsonify({"ok": True})


@app.post("/api/messages/send")
def send_message_http():
    payload = request.get_json(silent=True) or {}
    sender = str(payload.get("sender", "panel"))[:80]
    receiver = str(payload.get("receiver", "nodo-b"))[:80]
    key_name = str(payload.get("key_name", "default_caesar"))[:80]
    message = str(payload.get("message", ""))[:600]

    encrypted_result = encrypt_with_key(key_name, message)
    if encrypted_result is None:
        return jsonify({"ok": False, "error": "unknown_key"}), 404

    cipher_name, encrypted_payload = encrypted_result
    message_id = save_message(
        sender=sender,
        receiver=receiver,
        channel="http",
        key_name=key_name,
        cipher=cipher_name,
        encrypted_payload=encrypted_payload,
        plain_preview=message[:140],
        status="encrypted",
    )

    with state_lock:
        state["http_messages"] += 1

    return jsonify({"ok": True, "message_id": message_id, "encrypted_payload": encrypted_payload})


@app.post("/api/messages/decrypt")
def decrypt_message():
    payload = request.get_json(silent=True) or {}
    message_id = int(payload.get("message_id", 0))
    actor = str(payload.get("actor", "panel"))[:80]

    conn = db_conn()
    row = conn.execute(
        """
        SELECT id, key_name, encrypted_payload
        FROM messages
        WHERE id = ?
        """,
        (message_id,),
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "message_not_found"}), 404

    plain = decrypt_with_key(row["key_name"], row["encrypted_payload"])
    if plain is None:
        conn.close()
        return jsonify({"ok": False, "error": "key_not_found"}), 404

    conn.execute(
        """
        INSERT INTO decrypt_audit (message_id, created_at, actor, result_preview)
        VALUES (?, ?, ?, ?)
        """,
        (message_id, now_text(), actor, plain[:140]),
    )
    conn.commit()
    conn.close()

    with state_lock:
        state["decrypt_ops"] += 1

    return jsonify({"ok": True, "plain": plain})


@app.get("/api/messages")
def messages():
    limit = int(request.args.get("limit", 100))
    limit = max(10, min(limit, 500))

    conn = db_conn()
    rows = conn.execute(
        """
        SELECT id, created_at, sender, receiver, channel, key_name, cipher,
               encrypted_payload, plain_preview, status
        FROM messages
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    audits = conn.execute(
        """
        SELECT id, message_id, created_at, actor, result_preview
        FROM decrypt_audit
        ORDER BY id DESC
        LIMIT 80
        """
    ).fetchall()
    conn.close()

    return jsonify(
        {
            "ok": True,
            "items": [dict(r) for r in rows],
            "audits": [dict(r) for r in audits],
        }
    )


@app.get("/api/stats")
def stats():
    conn = db_conn()
    total_messages = conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"]
    by_cipher = conn.execute(
        """
        SELECT cipher, COUNT(*) AS c
        FROM messages
        GROUP BY cipher
        """
    ).fetchall()
    conn.close()

    cipher_map = {r["cipher"]: r["c"] for r in by_cipher}
    with state_lock:
        runtime = dict(state)

    return jsonify(
        {
            "ok": True,
            "total_messages": total_messages,
            "by_cipher": {
                "caesar": cipher_map.get("caesar", 0),
                "xor": cipher_map.get("xor", 0),
            },
            "runtime": runtime,
            "tcp_port": TCP_PORT,
        }
    )


if __name__ == "__main__":
    init_db()
    start_tcp_server()
    app.run(host="127.0.0.1", port=HTTP_PORT, debug=True)
