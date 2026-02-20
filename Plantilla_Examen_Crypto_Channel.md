# Crypto-Channel-Lab — Plantilla de Examen

**Alumno:** Luis Rodríguez Cedeño · **DNI:** 53945291X  
**Módulo:** Programación de Servicios y Procesos · **Curso:** DAM2 2025/26

---

## 1. Introducción

- **Qué es:** Sistema de comunicación cifrada con Caesar + XOR, servidor TCP multi-hilo, auditoría de descifrado
- **Contexto:** Módulo de PSP — cifrado simétrico, sockets TCP, concurrencia con ThreadingMixIn, patrón Factory
- **Objetivos principales:**
  - 2 cifrados: Caesar (desplazamiento mod 65536) y XOR (clave cíclica + base64)
  - Patrón Factory para selección dinámica de cifrado
  - Servidor TCP multi-hilo con `socketserver.ThreadingMixIn`
  - CRUD de claves de cifrado con SQLite
  - Auditoría de descifrado (quién descifró qué, cuándo)
- **Tecnologías clave:**
  - Python 3.11, `socketserver` (TCP), `threading` (ThreadingMixIn)
  - `base64` (codificación XOR), `hashlib` (no usado, pero contexto crypto)
  - Flask (API REST), SQLite, dataclasses
- **Arquitectura:** `app.py` (313 líneas: cifrados + TCP server + Flask API) → `tcp_secure_client.py` (cliente TCP de demo) → `templates/index.html` (dashboard) → `static/app.js`

---

## 2. Desarrollo de las partes

### 2.1 CaesarCipher — Desplazamiento Unicode

- `encrypt()`: desplaza cada carácter por `shift` posiciones (mod 65536, rango Unicode)
- `decrypt()`: desplaza en dirección opuesta (`-shift`)
- Soporta cualquier carácter Unicode, no solo ASCII

```python
class CaesarCipher:
    """Cifrado César con desplazamiento configurable sobre Unicode."""

    def __init__(self, shift: int = 3):
        self.shift = shift

    def encrypt(self, plaintext: str) -> str:
        return ''.join(
            chr((ord(c) + self.shift) % 65536) for c in plaintext
        )

    def decrypt(self, ciphertext: str) -> str:
        return ''.join(
            chr((ord(c) - self.shift) % 65536) for c in ciphertext
        )
```

> **Explicación:** `ord(c)` convierte carácter a código Unicode. Se suma el shift y se aplica módulo 65536 (rango BMP Unicode). Para descifrar, se resta. Es un cifrado simétrico simple: la misma clave (shift) cifra y descifra.

### 2.2 XorCipher — XOR cíclico con base64

- XOR byte a byte con clave cíclica: `byte_data[i] ^ key_bytes[i % len(key_bytes)]`
- Resultado en base64 para transmisión segura como texto
- Simétrico: `encrypt == decrypt` (XOR es su propia inversa)

```python
import base64

class XorCipher:
    """Cifrado XOR con clave cíclica y salida base64."""

    def __init__(self, key: str = "secret"):
        self.key = key

    def encrypt(self, plaintext: str) -> str:
        key_bytes = self.key.encode('utf-8')
        data_bytes = plaintext.encode('utf-8')
        xored = bytes(
            data_bytes[i] ^ key_bytes[i % len(key_bytes)]
            for i in range(len(data_bytes))
        )
        return base64.b64encode(xored).decode('ascii')

    def decrypt(self, ciphertext: str) -> str:
        key_bytes = self.key.encode('utf-8')
        data_bytes = base64.b64decode(ciphertext)
        xored = bytes(
            data_bytes[i] ^ key_bytes[i % len(key_bytes)]
            for i in range(len(data_bytes))
        )
        return xored.decode('utf-8')
```

> **Explicación:** XOR es reversible: `A ^ K ^ K = A`. Se convierte texto y clave a bytes. La clave se repite cíclicamente (`i % len(key_bytes)`). El resultado se codifica en base64 para poder transmitirlo como texto (ya que XOR produce bytes arbitrarios).

### 2.3 CipherFactory — Patrón Factory

- `from_key(key_config)` → devuelve instancia de CaesarCipher o XorCipher según nombre
- `KeyConfig` dataclass: tipo de cifrado + parámetros
- Desacopla la creación del uso del cifrado

```python
from dataclasses import dataclass

@dataclass
class KeyConfig:
    id: str
    name: str
    cipher_type: str   # 'caesar' o 'xor'
    cipher_param: str   # shift (caesar) o key (xor)
    created_at: str

class CipherFactory:
    """Factory para crear instancias de cifrado."""

    @staticmethod
    def from_key(key_config: KeyConfig):
        if key_config.cipher_type == 'caesar':
            return CaesarCipher(shift=int(key_config.cipher_param))
        elif key_config.cipher_type == 'xor':
            return XorCipher(key=key_config.cipher_param)
        else:
            raise ValueError(f"Tipo de cifrado desconocido: {key_config.cipher_type}")
```

> **Explicación:** Factory toma un `KeyConfig` (con tipo y parámetro) y devuelve la instancia correcta del cifrado. El resto del código no necesita saber qué cifrado se usa: llama `cipher.encrypt()` / `cipher.decrypt()` de forma uniforme.

### 2.4 Servidor TCP multi-hilo

- `socketserver.ThreadingTCPServer` + `StreamRequestHandler` → un hilo por conexión
- Protocolo JSON: cliente envía `{"action":"encrypt","key_id":"...","text":"..."}`
- Servidor responde con resultado cifrado/descifrado

```python
import socketserver
import json

class SecureTCPHandler(socketserver.StreamRequestHandler):
    """Maneja conexiones TCP individuales (un hilo por cliente)."""

    def handle(self):
        raw = self.rfile.readline().strip()
        if not raw:
            return
        try:
            msg = json.loads(raw.decode('utf-8'))
            action = msg.get('action')  # 'encrypt' o 'decrypt'
            key_id = msg.get('key_id')
            text = msg.get('text', '')

            # Buscar clave en SQLite
            key_config = load_key(key_id)
            cipher = CipherFactory.from_key(key_config)

            if action == 'encrypt':
                result = cipher.encrypt(text)
            else:
                result = cipher.decrypt(text)

            response = json.dumps({"ok": True, "result": result})
        except Exception as e:
            response = json.dumps({"ok": False, "error": str(e)})

        self.wfile.write((response + '\n').encode('utf-8'))

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

# Arranque en hilo separado
tcp_server = ThreadedTCPServer(('0.0.0.0', TCP_PORT), SecureTCPHandler)
tcp_thread = threading.Thread(target=tcp_server.serve_forever, daemon=True)
tcp_thread.start()
```

> **Explicación:** `ThreadingMixIn` crea un hilo nuevo por cada conexión TCP entrante. El handler lee una línea JSON, busca la clave en SQLite, crea el cipher vía Factory, ejecuta encrypt/decrypt y devuelve JSON. El servidor TCP corre en su propio hilo daemon.

### 2.5 Auditoría de descifrado

- Cada operación de descifrado se registra en tabla `decrypt_audit`
- Campos: key_id, timestamp, texto cifrado (parcial), éxito/fallo
- Endpoint `/api/stats` incluye contadores de auditoría

```python
def log_decrypt_audit(key_id: str, ciphertext: str, success: bool):
    """Registrar intento de descifrado para auditoría."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO decrypt_audit (ts, key_id, ciphertext_preview, success)
        VALUES (datetime('now'), ?, ?, ?)
    """, (key_id, ciphertext[:50], success))
    conn.commit()
    conn.close()

@app.post("/api/messages/decrypt")
def decrypt_message():
    data = request.get_json()
    key_config = load_key(data['key_id'])
    cipher = CipherFactory.from_key(key_config)
    try:
        result = cipher.decrypt(data['ciphertext'])
        log_decrypt_audit(data['key_id'], data['ciphertext'], True)
        return jsonify({"ok": True, "plaintext": result})
    except Exception:
        log_decrypt_audit(data['key_id'], data['ciphertext'], False)
        return jsonify({"ok": False, "error": "Descifrado fallido"}), 400
```

> **Explicación:** Cada intento de descifrado (exitoso o fallido) se registra con timestamp, key_id y preview del ciphertext. Esto proporciona trazabilidad y seguridad: se puede auditar quién usó qué clave para descifrar.

---

## 3. Presentación del proyecto

- **Flujo:** Crear clave (Caesar/XOR) → Cifrar mensaje → Enviar via TCP o HTTP → Descifrar → Auditoría registrada
- **Demo:** `python app.py` → crear claves → cifrar mensajes → ver auditoría → usar cliente TCP
- **Concurrencia:** TCP ThreadingMixIn (1 hilo/conexión) + Flask en paralelo

---

## 4. Conclusión

- **Competencias:** Cifrado simétrico (Caesar, XOR), sockets TCP, Factory pattern, ThreadingMixIn, auditoría
- **Conceptos PSP:** ThreadingMixIn para concurrencia TCP, hilos daemon, protocolo JSON sobre sockets
- **Seguridad:** XOR con clave + base64, auditoría de operaciones, claves almacenadas
- **Extensibilidad:** Nuevo cifrado = nueva clase + registro en CipherFactory
- **Valoración:** Combina criptografía clásica con networking TCP concurrente y trazabilidad
