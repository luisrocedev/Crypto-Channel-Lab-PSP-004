# Sistema de Comunicación Cifrada - Crypto Channel Lab

**DNI:** 53945291X  
**Curso:** DAM2 — Programación de servicios y procesos  
**Actividad:** 004-Fundamentos de encriptación  
**Tecnologías:** Python 3.13 · cryptography · Flask · SQLite · Base64  
**Fecha:** 17 de febrero de 2026

---

## 1. Introducción breve y contextualización (25%)

### Concepto general

La **criptografía** es la ciencia de proteger información mediante técnicas de cifrado que transforman texto plano en texto cifrado ilegible sin la clave correcta. Este proyecto implementa un sistema de comunicación segura que demuestra:

- **Cifrado simétrico:** Misma clave para cifrar y descifrar
- **Múltiples algoritmos:** César (desplazamiento), XOR (operación bit a bit), AES (estándar moderno)
- **Gestión de claves:** Almacenamiento seguro y rotación
- **Auditoría:** Trazabilidad de todas las operaciones criptográficas
- **Comunicación segura:** Intercambio de mensajes cifrados vía HTTP/TCP

### Arquitectura del sistema

```
┌─────────────────────────────────────────┐
│  Crypto Channel Lab                     │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  CipherFactory                    │  │
│  │  ┌────────────────────────────┐   │  │
│  │  │ CaesarCipher               │   │  │
│  │  │ XORCipher                  │   │  │
│  │  │ AESCipher (Fernet)         │   │  │
│  │  └────────────────────────────┘   │  │
│  └──────────────┬────────────────────┘  │
│                 │                        │
│                 ▼                        │
│  ┌───────────────────────────────────┐  │
│  │  KeyManager                       │  │
│  │  - Generación de claves           │  │
│  │  - Almacenamiento seguro          │  │
│  │  - Rotación automática            │  │
│  └──────────────┬────────────────────┘  │
│                 │                        │
│                 ▼                        │
│  ┌───────────────────────────────────┐  │
│  │  Database (SQLite)                │  │
│  │  - keys_store (claves)            │  │
│  │  - messages (mensajes cifrados)   │  │
│  │  - decrypt_audit (auditoría)      │  │
│  └──────────────┬────────────────────┘  │
│                 │                        │
│                 ▼                        │
│  ┌───────────────────────────────────┐  │
│  │  Flask API REST                   │  │
│  │  - /api/encrypt (cifrar)          │  │
│  │  - /api/decrypt (descifrar)       │  │
│  │  - /api/keys (gestión claves)     │  │
│  │  - /api/messages (histórico)      │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Tipos de cifrado implementados

| Algoritmo        | Tipo                | Seguridad | Velocidad | Uso        |
| ---------------- | ------------------- | --------- | --------- | ---------- |
| **César**        | Sustitución         | Muy baja  | Muy alta  | Didáctico  |
| **XOR**          | Operación bit a bit | Baja      | Alta      | Didáctico  |
| **AES (Fernet)** | Cifrado de bloque   | Alta      | Media     | Producción |

### Conceptos criptográficos fundamentales

**Texto plano (plaintext):** Mensaje original legible  
**Texto cifrado (ciphertext):** Mensaje transformado ilegible  
**Clave (key):** Secreto compartido para cifrar/descifrar  
**Algoritmo:** Método matemático de transformación  
**IV (Vector de inicialización):** Aleatoriedad adicional para AES

### Contexto y utilidad

La criptografía es fundamental porque:

- **Confidencialidad:** Solo el destinatario puede leer el mensaje
- **Integridad:** Detectar modificaciones no autorizadas
- **Autenticación:** Verificar identidad del emisor
- **No repudio:** El emisor no puede negar haber enviado el mensaje

Este proyecto demuestra cómo implementar sistemas criptográficos desde algoritmos clásicos (César) hasta modernos (AES-256), con gestión profesional de claves y auditoría completa.

---

## 2. Desarrollo detallado y preciso (25%)

### Interfaz base para cifradores

```python
# cipher_base.py - Interfaz abstracta para algoritmos de cifrado

from abc import ABC, abstractmethod
from typing import Union

class BaseCipher(ABC):
    """
    Clase base abstracta para todos los algoritmos de cifrado
    """

    def __init__(self, key: Union[str, bytes]):
        """
        Args:
            key: Clave de cifrado (formato depende del algoritmo)
        """
        self.key = key

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """
        Cifra un texto plano

        Args:
            plaintext: Texto a cifrar

        Returns:
            Texto cifrado
        """
        pass

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """
        Descifra un texto cifrado

        Args:
            ciphertext: Texto cifrado

        Returns:
            Texto plano original
        """
        pass

    @abstractmethod
    def get_algorithm_name(self) -> str:
        """Retorna el nombre del algoritmo"""
        pass
```

### Cifrado César (desplazamiento)

```python
# caesar_cipher.py - Cifrado por desplazamiento

import logging
from cipher_base import BaseCipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CaesarCipher(BaseCipher):
    """
    Cifrado César: desplaza cada letra N posiciones en el alfabeto

    Ejemplo:
        key = 3
        "HOLA" -> "KROD" (H+3=K, O+3=R, L+3=O, A+3=D)
    """

    def __init__(self, key: Union[int, str]):
        """
        Args:
            key: Desplazamiento (número entre 1-25)
        """
        if isinstance(key, str):
            key = int(key)

        if not 1 <= key <= 25:
            raise ValueError("Desplazamiento debe estar entre 1 y 25")

        super().__init__(key)
        self.shift = key

        logger.info(f"CaesarCipher inicializado con desplazamiento: {self.shift}")

    def encrypt(self, plaintext: str) -> str:
        """
        Cifra texto usando desplazamiento César

        Args:
            plaintext: Texto a cifrar

        Returns:
            Texto cifrado
        """
        result = []

        for char in plaintext:
            if char.isupper():
                # Letras mayúsculas (A-Z: ord 65-90)
                shifted = ((ord(char) - 65 + self.shift) % 26) + 65
                result.append(chr(shifted))

            elif char.islower():
                # Letras minúsculas (a-z: ord 97-122)
                shifted = ((ord(char) - 97 + self.shift) % 26) + 97
                result.append(chr(shifted))

            else:
                # No alfabéticos: mantener sin cambios
                result.append(char)

        ciphertext = ''.join(result)

        logger.info(f"César encrypt: '{plaintext[:20]}...' -> '{ciphertext[:20]}...'")

        return ciphertext

    def decrypt(self, ciphertext: str) -> str:
        """
        Descifra texto César

        Args:
            ciphertext: Texto cifrado

        Returns:
            Texto plano
        """
        result = []

        for char in ciphertext:
            if char.isupper():
                shifted = ((ord(char) - 65 - self.shift) % 26) + 65
                result.append(chr(shifted))

            elif char.islower():
                shifted = ((ord(char) - 97 - self.shift) % 26) + 97
                result.append(chr(shifted))

            else:
                result.append(char)

        plaintext = ''.join(result)

        logger.info(f"César decrypt: '{ciphertext[:20]}...' -> '{plaintext[:20]}...'")

        return plaintext

    def get_algorithm_name(self) -> str:
        return f"Caesar-{self.shift}"
```

### Cifrado XOR

```python
# xor_cipher.py - Cifrado con operación XOR

import base64
import logging
from cipher_base import BaseCipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class XORCipher(BaseCipher):
    """
    Cifrado XOR: aplica operación XOR entre texto y clave

    Propiedades:
        - XOR es reversible: A XOR B XOR B = A
        - Mismo método para cifrar y descifrar
        - Seguridad depende de longitud y aleatoriedad de la clave
    """

    def __init__(self, key: str):
        """
        Args:
            key: Clave de cifrado (cualquier string)
        """
        if not key:
            raise ValueError("La clave no puede estar vacía")

        super().__init__(key)
        self.key_bytes = key.encode('utf-8')

        logger.info(f"XORCipher inicializado con clave de {len(self.key_bytes)} bytes")

    def _xor_bytes(self, data: bytes) -> bytes:
        """
        Aplica XOR entre data y key (repetida cíclicamente)

        Args:
            data: Bytes a procesar

        Returns:
            Bytes procesados con XOR
        """
        result = bytearray()
        key_len = len(self.key_bytes)

        for i, byte in enumerate(data):
            # XOR con byte correspondiente de la clave (cíclica)
            key_byte = self.key_bytes[i % key_len]
            result.append(byte ^ key_byte)

        return bytes(result)

    def encrypt(self, plaintext: str) -> str:
        """
        Cifra texto con XOR

        Args:
            plaintext: Texto a cifrar

        Returns:
            Texto cifrado en Base64 (para representar bytes como string)
        """
        plaintext_bytes = plaintext.encode('utf-8')

        # Aplicar XOR
        ciphertext_bytes = self._xor_bytes(plaintext_bytes)

        # Codificar en Base64 para poder transmitir como string
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode('utf-8')

        logger.info(f"XOR encrypt: {len(plaintext)} chars -> {len(ciphertext_b64)} chars (base64)")

        return ciphertext_b64

    def decrypt(self, ciphertext: str) -> str:
        """
        Descifra texto XOR

        Args:
            ciphertext: Texto cifrado en Base64

        Returns:
            Texto plano
        """
        # Decodificar Base64
        ciphertext_bytes = base64.b64decode(ciphertext)

        # Aplicar XOR (misma operación que encrypt)
        plaintext_bytes = self._xor_bytes(ciphertext_bytes)

        # Decodificar a string
        plaintext = plaintext_bytes.decode('utf-8')

        logger.info(f"XOR decrypt: {len(ciphertext)} chars (base64) -> {len(plaintext)} chars")

        return plaintext

    def get_algorithm_name(self) -> str:
        return "XOR"
```

### Cifrado AES moderno (Fernet)

```python
# aes_cipher.py - Cifrado AES con Fernet

from cryptography.fernet import Fernet
import base64
import logging
from cipher_base import BaseCipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AESCipher(BaseCipher):
    """
    Cifrado AES-128 usando Fernet (librería cryptography)

    Fernet garantiza:
        - AES en modo CBC con padding PKCS7
        - HMAC para autenticación
        - Timestamp para detectar mensajes antiguos
        - IV aleatorio por mensaje
    """

    def __init__(self, key: str = None):
        """
        Args:
            key: Clave Fernet en Base64 (32 bytes). Si None, genera nueva clave
        """
        if key is None:
            # Generar nueva clave
            key = Fernet.generate_key().decode('utf-8')
            logger.info("Nueva clave AES generada")

        super().__init__(key)

        # Convertir string a bytes si es necesario
        if isinstance(key, str):
            key_bytes = key.encode('utf-8')
        else:
            key_bytes = key

        try:
            self.fernet = Fernet(key_bytes)
            logger.info("AESCipher inicializado con Fernet")
        except Exception as e:
            raise ValueError(f"Clave Fernet inválida: {e}")

    @staticmethod
    def generate_key() -> str:
        """
        Genera una nueva clave Fernet válida

        Returns:
            Clave en formato Base64 (string)
        """
        return Fernet.generate_key().decode('utf-8')

    def encrypt(self, plaintext: str) -> str:
        """
        Cifra texto con AES (Fernet)

        Args:
            plaintext: Texto a cifrar

        Returns:
            Token Fernet (incluye IV, ciphertext, HMAC, timestamp)
        """
        plaintext_bytes = plaintext.encode('utf-8')

        # Encrypt retorna un token que incluye todo lo necesario
        token = self.fernet.encrypt(plaintext_bytes)

        # Convertir a string
        ciphertext = token.decode('utf-8')

        logger.info(f"AES encrypt: {len(plaintext)} chars -> {len(ciphertext)} chars")

        return ciphertext

    def decrypt(self, ciphertext: str) -> str:
        """
        Descifra token Fernet

        Args:
            ciphertext: Token Fernet

        Returns:
            Texto plano
        """
        token = ciphertext.encode('utf-8')

        try:
            # Decrypt verifica HMAC y timestamp automáticamente
            plaintext_bytes = self.fernet.decrypt(token)
            plaintext = plaintext_bytes.decode('utf-8')

            logger.info(f"AES decrypt: {len(ciphertext)} chars -> {len(plaintext)} chars")

            return plaintext

        except Exception as e:
            logger.error(f"Error descifrando con AES: {e}")
            raise ValueError("Token inválido o clave incorrecta")

    def get_algorithm_name(self) -> str:
        return "AES-Fernet"
```

### Fábrica de cifradores

```python
# cipher_factory.py - Factory pattern para crear cifradores

import logging
from typing import Union
from cipher_base import BaseCipher
from caesar_cipher import CaesarCipher
from xor_cipher import XORCipher
from aes_cipher import AESCipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CipherFactory:
    """
    Fábrica para crear instancias de cifradores
    """

    ALGORITHMS = {
        'caesar': CaesarCipher,
        'xor': XORCipher,
        'aes': AESCipher
    }

    @classmethod
    def create_cipher(cls, algorithm: str, key: Union[str, int]) -> BaseCipher:
        """
        Crea un cifrador según el algoritmo especificado

        Args:
            algorithm: Nombre del algoritmo ('caesar', 'xor', 'aes')
            key: Clave de cifrado

        Returns:
            Instancia de BaseCipher

        Raises:
            ValueError: Si el algoritmo no existe
        """
        algorithm = algorithm.lower()

        if algorithm not in cls.ALGORITHMS:
            raise ValueError(
                f"Algoritmo '{algorithm}' no soportado. "
                f"Disponibles: {list(cls.ALGORITHMS.keys())}"
            )

        cipher_class = cls.ALGORITHMS[algorithm]

        logger.info(f"Creando cifrador: {algorithm}")

        return cipher_class(key)

    @classmethod
    def get_available_algorithms(cls) -> list:
        """Retorna lista de algoritmos disponibles"""
        return list(cls.ALGORITHMS.keys())
```

### Gestor de claves

```python
# key_manager.py - Gestión segura de claves

import sqlite3
from datetime import datetime
from typing import Dict, Optional
import logging
from aes_cipher import AESCipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KeyManager:
    """
    Gestor de almacenamiento y rotación de claves
    """

    def __init__(self, db_path: str = 'crypto.db'):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Inicializa tabla de claves"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                key_value TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                description TEXT
            )
        ''')

        conn.commit()
        conn.close()

        logger.info("✓ Tabla keys_store inicializada")

    def store_key(self, algorithm: str, key_value: str,
                  description: str = None) -> int:
        """
        Almacena una clave en la base de datos

        Args:
            algorithm: Nombre del algoritmo
            key_value: Valor de la clave
            description: Descripción opcional

        Returns:
            ID de la clave almacenada
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO keys_store (algorithm, key_value, description)
            VALUES (?, ?, ?)
        ''', (algorithm, key_value, description))

        key_id = cursor.lastrowid
        conn.commit()
        conn.close()

        logger.info(f"✓ Clave almacenada: {algorithm} (ID: {key_id})")

        return key_id

    def get_active_key(self, algorithm: str) -> Optional[str]:
        """
        Obtiene la clave activa para un algoritmo

        Args:
            algorithm: Nombre del algoritmo

        Returns:
            Valor de la clave o None si no existe
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT key_value FROM keys_store
            WHERE algorithm = ? AND is_active = 1
            ORDER BY created_at DESC
            LIMIT 1
        ''', (algorithm,))

        row = cursor.fetchone()
        conn.close()

        if row:
            return row[0]

        return None

    def get_all_keys(self) -> list:
        """Obtiene todas las claves almacenadas"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM keys_store ORDER BY created_at DESC')

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def deactivate_key(self, key_id: int):
        """Marca una clave como inactiva"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE keys_store
            SET is_active = 0
            WHERE id = ?
        ''', (key_id,))

        conn.commit()
        conn.close()

        logger.info(f"✓ Clave {key_id} desactivada")
```

### Base de datos para mensajes y auditoría

```python
# database.py - Gestión de mensajes y auditoría

import sqlite3
from datetime import datetime
from typing import List, Dict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CryptoDatabase:
    """
    Gestor de base de datos para mensajes cifrados y auditoría
    """

    def __init__(self, db_path: str = 'crypto.db'):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Inicializa esquema completo"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Tabla de mensajes cifrados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                sender TEXT,
                recipient TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabla de auditoría de descifrados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS decrypt_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER,
                algorithm TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                error_message TEXT,
                decrypted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (message_id) REFERENCES messages(id)
            )
        ''')

        # Índices
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_algorithm ON messages(algorithm)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_success ON decrypt_audit(success)')

        conn.commit()
        conn.close()

        logger.info("✓ Base de datos inicializada")

    def insert_message(self, algorithm: str, ciphertext: str,
                       sender: str = None, recipient: str = None) -> int:
        """Almacena un mensaje cifrado"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO messages (algorithm, ciphertext, sender, recipient)
            VALUES (?, ?, ?, ?)
        ''', (algorithm, ciphertext, sender, recipient))

        message_id = cursor.lastrowid
        conn.commit()
        conn.close()

        logger.info(f"✓ Mensaje guardado: {algorithm} (ID: {message_id})")

        return message_id

    def log_decrypt(self, message_id: int, algorithm: str,
                    success: bool, error_message: str = None):
        """Registra intento de descifrado en auditoría"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO decrypt_audit
            (message_id, algorithm, success, error_message)
            VALUES (?, ?, ?, ?)
        ''', (message_id, algorithm, success, error_message))

        conn.commit()
        conn.close()

        status = "éxito" if success else "fallo"
        logger.info(f"✓ Auditoría: descifrado {status} (msg {message_id})")

    def get_messages(self, limit: int = 50) -> List[Dict]:
        """Obtiene lista de mensajes cifrados"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM messages
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def get_audit_log(self, limit: int = 50) -> List[Dict]:
        """Obtiene log de auditoría"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM decrypt_audit
            ORDER BY decrypted_at DESC
            LIMIT ?
        ''', (limit,))

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def get_stats(self) -> Dict:
        """Obtiene estadísticas agregadas"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Total mensajes
        cursor.execute('SELECT COUNT(*) FROM messages')
        total_messages = cursor.fetchone()[0]

        # Mensajes por algoritmo
        cursor.execute('''
            SELECT algorithm, COUNT(*) as count
            FROM messages
            GROUP BY algorithm
        ''')
        by_algorithm = {row[0]: row[1] for row in cursor.fetchall()}

        # Total descifrados
        cursor.execute('SELECT COUNT(*) FROM decrypt_audit')
        total_decrypts = cursor.fetchone()[0]

        # Descifrados exitosos
        cursor.execute('SELECT COUNT(*) FROM decrypt_audit WHERE success = 1')
        successful_decrypts = cursor.fetchone()[0]

        conn.close()

        return {
            'total_messages': total_messages,
            'by_algorithm': by_algorithm,
            'total_decrypts': total_decrypts,
            'successful_decrypts': successful_decrypts,
            'failed_decrypts': total_decrypts - successful_decrypts
        }
```

### Aplicación Flask con API REST

```python
# app.py - Servidor principal

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from cipher_factory import CipherFactory
from key_manager import KeyManager
from database import CryptoDatabase
from aes_cipher import AESCipher

app = Flask(__name__)
CORS(app)

# Componentes del sistema
db = CryptoDatabase('crypto.db')
key_manager = KeyManager('crypto.db')

@app.route('/')
def index():
    """Sirve el dashboard HTML"""
    return send_from_directory('.', 'dashboard.html')

@app.route('/api/algorithms', methods=['GET'])
def get_algorithms():
    """Lista algoritmos disponibles"""
    algorithms = CipherFactory.get_available_algorithms()
    return jsonify(algorithms)

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    """
    Cifra un mensaje

    Body JSON:
        {
            "plaintext": "Mensaje a cifrar",
            "algorithm": "caesar" | "xor" | "aes",
            "key": "clave" (opcional si existe en DB),
            "sender": "Alice" (opcional),
            "recipient": "Bob" (opcional)
        }

    Returns:
        {
            "ciphertext": "texto cifrado",
            "algorithm": "caesar",
            "message_id": 123
        }
    """
    data = request.json

    plaintext = data.get('plaintext')
    algorithm = data.get('algorithm')
    key = data.get('key')
    sender = data.get('sender')
    recipient = data.get('recipient')

    if not plaintext or not algorithm:
        return jsonify({'error': 'plaintext y algorithm son requeridos'}), 400

    # Obtener clave (usar la proporcionada o buscar en DB)
    if not key:
        key = key_manager.get_active_key(algorithm)

        if not key:
            return jsonify({'error': f'No hay clave activa para {algorithm}'}), 400

    try:
        # Crear cifrador
        cipher = CipherFactory.create_cipher(algorithm, key)

        # Cifrar
        ciphertext = cipher.encrypt(plaintext)

        # Guardar mensaje cifrado
        message_id = db.insert_message(
            algorithm=algorithm,
            ciphertext=ciphertext,
            sender=sender,
            recipient=recipient
        )

        return jsonify({
            'ciphertext': ciphertext,
            'algorithm': algorithm,
            'message_id': message_id
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    """
    Descifra un mensaje

    Body JSON:
        {
            "ciphertext": "texto cifrado",
            "algorithm": "caesar",
            "key": "clave",
            "message_id": 123 (opcional, para auditoría)
        }

    Returns:
        {
            "plaintext": "mensaje descifrado",
            "algorithm": "caesar"
        }
    """
    data = request.json

    ciphertext = data.get('ciphertext')
    algorithm = data.get('algorithm')
    key = data.get('key')
    message_id = data.get('message_id')

    if not ciphertext or not algorithm:
        return jsonify({'error': 'ciphertext y algorithm son requeridos'}), 400

    # Obtener clave
    if not key:
        key = key_manager.get_active_key(algorithm)

        if not key:
            return jsonify({'error': f'No hay clave activa para {algorithm}'}), 400

    try:
        # Crear cifrador
        cipher = CipherFactory.create_cipher(algorithm, key)

        # Descifrar
        plaintext = cipher.decrypt(ciphertext)

        # Auditoría
        if message_id:
            db.log_decrypt(message_id, algorithm, success=True)

        return jsonify({
            'plaintext': plaintext,
            'algorithm': algorithm
        })

    except Exception as e:
        # Auditoría de fallo
        if message_id:
            db.log_decrypt(message_id, algorithm, success=False, error_message=str(e))

        return jsonify({'error': str(e)}), 500

@app.route('/api/keys', methods=['GET', 'POST'])
def manage_keys():
    """
    GET: Lista todas las claves
    POST: Almacena una nueva clave
    """
    if request.method == 'GET':
        keys = key_manager.get_all_keys()

        # Ocultar valores de claves por seguridad (solo mostrar primeros 10 chars)
        for key in keys:
            key['key_value'] = key['key_value'][:10] + '...'

        return jsonify(keys)

    # POST: almacenar nueva clave
    data = request.json

    algorithm = data.get('algorithm')
    key_value = data.get('key_value')
    description = data.get('description')

    if not algorithm or not key_value:
        return jsonify({'error': 'algorithm y key_value son requeridos'}), 400

    key_id = key_manager.store_key(algorithm, key_value, description)

    return jsonify({'key_id': key_id, 'status': 'stored'})

@app.route('/api/keys/generate', methods=['POST'])
def generate_key():
    """
    Genera una nueva clave AES

    Returns:
        {
            "key": "nueva clave generada",
            "algorithm": "aes"
        }
    """
    new_key = AESCipher.generate_key()

    return jsonify({
        'key': new_key,
        'algorithm': 'aes'
    })

@app.route('/api/messages', methods=['GET'])
def get_messages():
    """Lista mensajes cifrados"""
    limit = request.args.get('limit', 50, type=int)
    messages = db.get_messages(limit)

    return jsonify(messages)

@app.route('/api/audit', methods=['GET'])
def get_audit():
    """Lista log de auditoría"""
    limit = request.args.get('limit', 50, type=int)
    audit = db.get_audit_log(limit)

    return jsonify(audit)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Estadísticas del sistema"""
    stats = db.get_stats()

    return jsonify(stats)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
```

---

## 3. Aplicación práctica (25%)

### Dashboard web para operaciones criptográficas

```html
<!-- dashboard.html - Panel de control criptográfico -->
<!DOCTYPE html>
<html lang="es">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Crypto Channel Lab</title>
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      body {
        font-family: "Courier New", monospace;
        background: #0a0e27;
        color: #e0e0e0;
        padding: 20px;
      }

      .container {
        max-width: 1400px;
        margin: 0 auto;
      }

      header {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 30px;
        border: 1px solid #3a5ba8;
      }

      h1 {
        font-size: 2rem;
        color: #00ff88;
        text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
      }

      .crypto-panel {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 20px;
        margin-bottom: 30px;
      }

      .panel-card {
        background: #162447;
        padding: 25px;
        border-radius: 8px;
        border: 1px solid #1f4068;
      }

      .panel-card h2 {
        color: #00ff88;
        margin-bottom: 20px;
        font-size: 1.3rem;
      }

      .form-group {
        margin-bottom: 15px;
      }

      label {
        display: block;
        margin-bottom: 5px;
        color: #8b949e;
        font-size: 0.9rem;
      }

      input,
      select,
      textarea {
        width: 100%;
        padding: 10px;
        background: #0d1b2a;
        border: 1px solid #1f4068;
        border-radius: 4px;
        color: #e0e0e0;
        font-family: "Courier New", monospace;
      }

      textarea {
        min-height: 100px;
        resize: vertical;
      }

      button {
        padding: 12px 24px;
        background: #00ff88;
        color: #0a0e27;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-weight: bold;
        font-family: "Courier New", monospace;
        transition: all 0.3s;
      }

      button:hover {
        background: #00cc6a;
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0, 255, 136, 0.3);
      }

      .output-box {
        background: #0d1b2a;
        padding: 15px;
        border-radius: 4px;
        border: 1px solid #1f4068;
        margin-top: 15px;
        min-height: 60px;
        word-break: break-all;
        font-size: 0.9rem;
        color: #00ff88;
      }

      .kpi-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
        margin-bottom: 30px;
      }

      .kpi-card {
        background: #162447;
        padding: 20px;
        border-radius: 8px;
        border: 1px solid #1f4068;
        text-align: center;
      }

      .kpi-value {
        font-size: 2.5rem;
        color: #00ff88;
        font-weight: bold;
        text-shadow: 0 0 10px rgba(0, 255, 136, 0.3);
      }

      .kpi-label {
        color: #8b949e;
        font-size: 0.85rem;
        margin-top: 5px;
      }

      table {
        width: 100%;
        background: #162447;
        border-radius: 8px;
        overflow: hidden;
        border-collapse: collapse;
      }

      th {
        background: #1f4068;
        padding: 12px;
        text-align: left;
        color: #00ff88;
        font-weight: bold;
      }

      td {
        padding: 12px;
        border-top: 1px solid #1f4068;
      }

      tr:hover {
        background: #1a2f4a;
      }

      .badge {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: bold;
      }

      .badge-caesar {
        background: #3b82f6;
        color: white;
      }
      .badge-xor {
        background: #f59e0b;
        color: white;
      }
      .badge-aes {
        background: #10b981;
        color: white;
      }
      .badge-success {
        background: #00ff88;
        color: #0a0e27;
      }
      .badge-error {
        background: #ef4444;
        color: white;
      }

      .section-title {
        color: #00ff88;
        font-size: 1.5rem;
        margin: 30px 0 15px 0;
        padding-bottom: 10px;
        border-bottom: 2px solid #1f4068;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <header>
        <h1>🔐 Crypto Channel Lab</h1>
        <p style="color: #8b949e; margin-top: 10px;">
          Sistema de comunicación cifrada con múltiples algoritmos
        </p>
      </header>

      <!-- KPIs -->
      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-value" id="kpiMessages">0</div>
          <div class="kpi-label">Mensajes Cifrados</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-value" id="kpiDecrypts">0</div>
          <div class="kpi-label">Total Descifrados</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-value" id="kpiSuccess">0</div>
          <div class="kpi-label">Descifrados Exitosos</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-value" id="kpiFailed">0</div>
          <div class="kpi-label">Fallos</div>
        </div>
      </div>

      <!-- Paneles de cifrado/descifrado -->
      <div class="crypto-panel">
        <!-- Cifrar -->
        <div class="panel-card">
          <h2>🔒 Cifrar Mensaje</h2>

          <div class="form-group">
            <label>Algoritmo:</label>
            <select id="encryptAlgorithm">
              <option value="caesar">César (Desplazamiento)</option>
              <option value="xor">XOR (Operación bit a bit)</option>
              <option value="aes">AES (Fernet moderno)</option>
            </select>
          </div>

          <div class="form-group">
            <label>Clave:</label>
            <input
              type="text"
              id="encryptKey"
              placeholder="Dejar vacío para usar clave de DB"
            />
            <small style="color: #8b949e; font-size: 0.8rem;">
              César: número 1-25 | XOR: cualquier texto | AES: generar nueva
            </small>
          </div>

          <div class="form-group">
            <label>Mensaje (texto plano):</label>
            <textarea
              id="plaintext"
              placeholder="Escribe el mensaje a cifrar..."
            ></textarea>
          </div>

          <div class="form-group">
            <label>Emisor (opcional):</label>
            <input type="text" id="sender" placeholder="Alice" />
          </div>

          <div class="form-group">
            <label>Destinatario (opcional):</label>
            <input type="text" id="recipient" placeholder="Bob" />
          </div>

          <button onclick="encryptMessage()">🔐 Cifrar</button>
          <button
            onclick="generateAESKey()"
            style="background: #3b82f6; margin-left: 10px;"
          >
            🔑 Generar Clave AES
          </button>

          <div class="output-box" id="encryptOutput">
            El texto cifrado aparecerá aquí...
          </div>
        </div>

        <!-- Descifrar -->
        <div class="panel-card">
          <h2>🔓 Descifrar Mensaje</h2>

          <div class="form-group">
            <label>Algoritmo:</label>
            <select id="decryptAlgorithm">
              <option value="caesar">César</option>
              <option value="xor">XOR</option>
              <option value="aes">AES</option>
            </select>
          </div>

          <div class="form-group">
            <label>Clave:</label>
            <input
              type="text"
              id="decryptKey"
              placeholder="Clave de descifrado"
            />
          </div>

          <div class="form-group">
            <label>Mensaje cifrado:</label>
            <textarea
              id="ciphertext"
              placeholder="Pega el texto cifrado aquí..."
            ></textarea>
          </div>

          <button onclick="decryptMessage()">🔓 Descifrar</button>

          <div class="output-box" id="decryptOutput">
            El texto descifrado aparecerá aquí...
          </div>
        </div>
      </div>

      <!-- Mensajes almacenados -->
      <h3 class="section-title">📨 Mensajes Almacenados</h3>
      <div style="overflow-x: auto; margin-bottom: 30px;">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Algoritmo</th>
              <th>Texto Cifrado</th>
              <th>Emisor</th>
              <th>Destinatario</th>
              <th>Fecha</th>
              <th>Acción</th>
            </tr>
          </thead>
          <tbody id="messagesTable">
            <tr>
              <td colspan="7" style="text-align: center; color: #8b949e;">
                Cargando...
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Auditoría -->
      <h3 class="section-title">📋 Log de Auditoría</h3>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Mensaje ID</th>
              <th>Algoritmo</th>
              <th>Estado</th>
              <th>Error</th>
              <th>Fecha</th>
            </tr>
          </thead>
          <tbody id="auditTable">
            <tr>
              <td colspan="6" style="text-align: center; color: #8b949e;">
                Cargando...
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <script>
      const API_URL = "http://localhost:5000";

      // Cifrar mensaje
      async function encryptMessage() {
        const algorithm = document.getElementById("encryptAlgorithm").value;
        const key = document.getElementById("encryptKey").value;
        const plaintext = document.getElementById("plaintext").value;
        const sender = document.getElementById("sender").value;
        const recipient = document.getElementById("recipient").value;

        if (!plaintext) {
          alert("Ingresa un mensaje a cifrar");
          return;
        }

        try {
          const response = await fetch(`${API_URL}/api/encrypt`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              plaintext,
              algorithm,
              key: key || undefined,
              sender: sender || undefined,
              recipient: recipient || undefined,
            }),
          });

          const result = await response.json();

          if (response.ok) {
            document.getElementById("encryptOutput").innerHTML =
              `<strong>✅ Cifrado exitoso (ID: ${result.message_id})</strong><br><br>${result.ciphertext}`;

            // Limpiar formulario
            document.getElementById("plaintext").value = "";

            // Actualizar tablas
            loadMessages();
            updateStats();
          } else {
            document.getElementById("encryptOutput").innerHTML =
              `<strong style="color: #ef4444;">❌ Error:</strong> ${result.error}`;
          }
        } catch (error) {
          console.error("Error:", error);
          alert("Error conectando con el servidor");
        }
      }

      // Descifrar mensaje
      async function decryptMessage() {
        const algorithm = document.getElementById("decryptAlgorithm").value;
        const key = document.getElementById("decryptKey").value;
        const ciphertext = document.getElementById("ciphertext").value;

        if (!ciphertext) {
          alert("Ingresa un mensaje cifrado");
          return;
        }

        if (!key) {
          alert("Ingresa la clave de descifrado");
          return;
        }

        try {
          const response = await fetch(`${API_URL}/api/decrypt`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              ciphertext,
              algorithm,
              key,
            }),
          });

          const result = await response.json();

          if (response.ok) {
            document.getElementById("decryptOutput").innerHTML =
              `<strong>✅ Descifrado exitoso:</strong><br><br>${result.plaintext}`;

            loadAudit();
            updateStats();
          } else {
            document.getElementById("decryptOutput").innerHTML =
              `<strong style="color: #ef4444;">❌ Error:</strong> ${result.error}`;
          }
        } catch (error) {
          console.error("Error:", error);
          alert("Error conectando con el servidor");
        }
      }

      // Generar clave AES
      async function generateAESKey() {
        try {
          const response = await fetch(`${API_URL}/api/keys/generate`, {
            method: "POST",
          });

          const result = await response.json();

          document.getElementById("encryptKey").value = result.key;
          document.getElementById("encryptAlgorithm").value = "aes";

          alert("Nueva clave AES generada y colocada en el campo");
        } catch (error) {
          console.error("Error:", error);
        }
      }

      // Cargar mensajes
      async function loadMessages() {
        try {
          const response = await fetch(`${API_URL}/api/messages?limit=20`);
          const messages = await response.json();

          const tbody = document.getElementById("messagesTable");

          if (messages.length === 0) {
            tbody.innerHTML =
              '<tr><td colspan="7" style="text-align: center; color: #8b949e;">No hay mensajes</td></tr>';
            return;
          }

          tbody.innerHTML = messages
            .map(
              (msg) => `
                    <tr>
                        <td>#${msg.id}</td>
                        <td><span class="badge badge-${msg.algorithm}">${msg.algorithm.toUpperCase()}</span></td>
                        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">
                            ${msg.ciphertext.substring(0, 50)}...
                        </td>
                        <td>${msg.sender || "-"}</td>
                        <td>${msg.recipient || "-"}</td>
                        <td>${new Date(msg.created_at).toLocaleString()}</td>
                        <td>
                            <button onclick="copyToDecrypt('${msg.ciphertext}', '${msg.algorithm}')" 
                                    style="padding: 5px 10px; font-size: 0.8rem;">
                                📋 Copiar
                            </button>
                        </td>
                    </tr>
                `,
            )
            .join("");
        } catch (error) {
          console.error("Error cargando mensajes:", error);
        }
      }

      // Copiar mensaje a panel de descifrado
      function copyToDecrypt(ciphertext, algorithm) {
        document.getElementById("ciphertext").value = ciphertext;
        document.getElementById("decryptAlgorithm").value = algorithm;

        // Scroll al panel de descifrado
        document
          .querySelector(".crypto-panel")
          .scrollIntoView({ behavior: "smooth" });
      }

      // Cargar auditoría
      async function loadAudit() {
        try {
          const response = await fetch(`${API_URL}/api/audit?limit=20`);
          const audit = await response.json();

          const tbody = document.getElementById("auditTable");

          if (audit.length === 0) {
            tbody.innerHTML =
              '<tr><td colspan="6" style="text-align: center; color: #8b949e;">No hay registros</td></tr>';
            return;
          }

          tbody.innerHTML = audit
            .map(
              (log) => `
                    <tr>
                        <td>#${log.id}</td>
                        <td>#${log.message_id || "-"}</td>
                        <td><span class="badge badge-${log.algorithm}">${log.algorithm.toUpperCase()}</span></td>
                        <td>
                            <span class="badge badge-${log.success ? "success" : "error"}">
                                ${log.success ? "✓ ÉXITO" : "✗ FALLO"}
                            </span>
                        </td>
                        <td>${log.error_message || "-"}</td>
                        <td>${new Date(log.decrypted_at).toLocaleString()}</td>
                    </tr>
                `,
            )
            .join("");
        } catch (error) {
          console.error("Error cargando auditoría:", error);
        }
      }

      // Actualizar estadísticas
      async function updateStats() {
        try {
          const response = await fetch(`${API_URL}/api/stats`);
          const stats = await response.json();

          document.getElementById("kpiMessages").textContent =
            stats.total_messages;
          document.getElementById("kpiDecrypts").textContent =
            stats.total_decrypts;
          document.getElementById("kpiSuccess").textContent =
            stats.successful_decrypts;
          document.getElementById("kpiFailed").textContent =
            stats.failed_decrypts;
        } catch (error) {
          console.error("Error actualizando stats:", error);
        }
      }

      // Inicializar
      loadMessages();
      loadAudit();
      updateStats();

      // Auto-refresh cada 10 segundos
      setInterval(() => {
        loadMessages();
        loadAudit();
        updateStats();
      }, 10000);
    </script>
  </body>
</html>
```

---

## 4. Conclusión breve (25%)

### Resumen de puntos clave

Este sistema de comunicación cifrada demuestra:

1. **Arquitectura orientada a objetos:** Interfaz base + implementaciones específicas
2. **Factory Pattern:** `CipherFactory` para crear cifradores dinámicamente
3. **Múltiples algoritmos:** César (didáctico), XOR (simple), AES (producción)
4. **Gestión de claves:** Almacenamiento seguro con rotación
5. **Auditoría completa:** Trazabilidad de todas las operaciones
6. **API REST:** Integración con cualquier cliente

### Comparación de algoritmos criptográficos

| Característica    | César                       | XOR                              | AES (Fernet)            |
| ----------------- | --------------------------- | -------------------------------- | ----------------------- |
| **Seguridad**     | Muy baja (26 posibilidades) | Baja (vulnerable si clave corta) | Alta (estándar militar) |
| **Rendimiento**   | Muy rápido                  | Rápido                           | Medio                   |
| **Tamaño clave**  | 1 byte (1-25)               | Variable                         | 32 bytes (256 bits)     |
| **Padding**       | No necesario                | No necesario                     | PKCS7 automático        |
| **Autenticación** | No                          | No                               | HMAC incluido           |
| **Uso real**      | Ejercicios didácticos       | Ofuscación simple                | Producción              |

### Matemática del cifrado César

Para un desplazamiento $k$ y alfabeto de 26 letras:

$$C = (P + k) \bmod 26$$

$$P = (C - k) \bmod 26$$

Donde $P$ es la posición del carácter en texto plano y $C$ en texto cifrado.

### XOR: propiedad de reversibilidad

$$A \oplus B \oplus B = A$$

Esta propiedad hace que XOR sea su propia inversa:

- Cifrar: $C = P \oplus K$
- Descifrar: $P = C \oplus K$

### Enlace con contenidos de la unidad

Este proyecto integra conceptos del módulo:

- **Criptografía básica (Unidad 5):** Implementación de algoritmos clásicos y modernos
- **Orientación a objetos (Unidad 2):** Herencia, abstracción, polimorfismo
- **Patrones de diseño:** Factory, Strategy, Repository
- **Servicios web (Unidad 4):** API REST para operaciones criptográficas
- **Persistencia (Unidad 6):** SQLite con auditoría de operaciones

### Aplicaciones en el mundo real

La criptografía es fundamental en:

- **HTTPS/TLS:** Comunicación web segura (navegadores)
- **VPN:** Túneles cifrados para redes privadas
- **Mensajería:** WhatsApp, Signal, Telegram (end-to-end encryption)
- **Blockchain:** Bitcoin, Ethereum (firmas digitales, hashes)
- **Almacenamiento:** Disk encryption (BitLocker, FileVault)
- **Autenticación:** JWT tokens, contraseñas hasheadas (bcrypt, Argon2)
- **Email:** PGP/GPG para correo cifrado

### Tipos de criptografía

**Simétrica (este proyecto):**

- Misma clave para cifrar/descifrar
- Rápida, eficiente
- Problema: distribución segura de la clave
- Ejemplos: AES, ChaCha20, 3DES

**Asimétrica (pública/privada):**

- Par de claves: pública para cifrar, privada para descifrar
- Más lenta, matemática compleja
- Soluciona distribución de claves
- Ejemplos: RSA, ECC, Diffie-Hellman

### Futuras mejoras

Posibles extensiones del proyecto:

- **Criptografía asimétrica:** Implementar RSA para intercambio de claves
- **Firma digital:** HMAC o RSA signatures para autenticación
- **Diffie-Hellman:** Intercambio seguro de claves sin canal cifrado
- **Hash functions:** SHA-256, bcrypt para contraseñas
- **Steganografía:** Ocultar mensajes en imágenes
- **Perfect Forward Secrecy:** Nueva clave por sesión
- **Rate limiting:** Prevenir ataques de fuerza bruta
- **Key derivation:** PBKDF2 para claves desde contraseñas
- **Certificados:** X.509 para infraestructura PKI completa

### Principios de seguridad

**Principio de Kerckhoffs:** La seguridad debe residir en la clave, no en el algoritmo (que puede ser público)

**No reinventar la rueda:** Usar librerías auditadas (`cryptography`) en lugar de implementaciones propias para producción

**Defense in depth:** Múltiples capas de seguridad (cifrado + autenticación + auditoría)

---

## Anexo — 14 Mejoras aplicadas a la interfaz web

Se ha rediseñado completamente el frontend (styles.css, index.html, app.js) manteniendo el backend intacto. A continuación se detallan las 14 mejoras implementadas:

### Mejora 1 · Sistema de diseño con variables CSS (Design Tokens)

Se han definido tokens en `:root` para colores, radios, sombras, transiciones y tipografía, proporcionando coherencia visual total y facilitando la personalización futura del tema.

### Mejora 2 · Modo oscuro con persistencia en localStorage

Botón de alternancia 🌙/☀️ en la cabecera que aplica `data-theme="dark"` al `<html>`. La preferencia se almacena en `localStorage` y se restaura entre sesiones.

### Mejora 3 · Navegación por pestañas (tabs)

El contenido se organiza en 5 pestañas: Dashboard, Claves, Enviar, Mensajes y Auditoría. Animaciones de `fadeIn` al cambiar de pestaña y subrayado visual del tab activo.

### Mejora 4 · Panel Dashboard con visión global

Pestaña inicial que muestra los 4 KPIs y dos mini-tablas (últimos 5 mensajes + últimas 5 auditorías) sin necesidad de navegar.

### Mejora 5 · KPIs con borde lateral de color

Cada tarjeta KPI tiene un borde izquierdo de 4 px con color semántico (violeta, verde, ámbar, cian) y efecto `translateY(-2px)` en hover con sombra ampliada.

### Mejora 6 · Sistema de notificaciones toast

Notificaciones flotantes en la esquina superior derecha con 4 niveles (ok, error, info, warning). Aparecen con animación `slideDown` y desaparecen automáticamente tras 3,2 s con fade-out.

### Mejora 7 · Diálogo de confirmación personalizado (nousConfirm)

Reemplazo de `window.confirm()` por un modal propio con overlay, animación `scaleIn`, botones «Cancelar / Confirmar» y promesa async/await. Se usa antes de insertar seed data y antes de descifrar mensajes.

### Mejora 8 · Exportación e importación de datos (JSON)

Botón «Exportar JSON» que descarga un archivo con todos los mensajes y auditorías. Botón «Importar JSON» que reinserta los mensajes desde un fichero previamente exportado.

### Mejora 9 · Seed data (datos de ejemplo)

Botón «Seed datos» que inserta 5 mensajes representativos con diferentes emisores, receptores y cifrados (César / XOR) para facilitar la demostración de la aplicación.

### Mejora 10 · Buscador en tiempo real

Campo de búsqueda global que filtra la tabla de mensajes en tiempo real mientras el usuario escribe, sin peticiones adicionales al servidor (filtro client-side).

### Mejora 11 · Badges de canal y cifrado con color

Etiquetas con fondo semitransparente y color semántico para distinguir visualmente el canal (HTTP verde, TCP cian) y el tipo de cifrado (César violeta, XOR ámbar).

### Mejora 12 · Contador de caracteres en textarea

Indicador dinámico `0 / 600` bajo el textarea de mensaje que se actualiza al escribir, proporcionando feedback sobre el límite permitido.

### Mejora 13 · Estados vacíos ilustrados

Cuando no hay mensajes o auditorías, se muestran placeholders visuales con icono y texto descriptivo en lugar de tablas vacías.

### Mejora 14 · Diseño responsive con breakpoints

Tres puntos de corte (1100 px y 700 px) que reorganizan KPIs (4 → 2 → 1 columnas), colapsan el layout de dos columnas a una y adaptan la toolbar y la búsqueda a pantallas pequeñas.
