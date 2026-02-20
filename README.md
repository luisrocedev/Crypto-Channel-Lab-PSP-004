<p align="center">
  <img src="https://img.shields.io/badge/Crypto_Channel_Lab-v2.0-7c3aed?style=for-the-badge" alt="Crypto Channel Lab v2.0" />
  <img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Flask-3.x-000?style=for-the-badge&logo=flask" alt="Flask" />
  <img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT" />
</p>

<h1 align="center">🔐 Crypto Channel Lab</h1>

<p align="center">
  <strong>Plataforma de cifrado y comunicación segura en tiempo real</strong><br/>
  Cifrado César · XOR · Canal TCP multihilo · Dashboard interactivo · Dark mode
</p>

---

## 🚀 ¿Qué es Crypto Channel Lab?

**Crypto Channel Lab** es un laboratorio profesional de criptografía aplicada que unifica **cifrado simétrico**, **comunicación TCP segura** y **auditoría completa** en una única plataforma web moderna. Diseñado como solución integral para explorar, demostrar y verificar distintos algoritmos de encriptación sobre canales de red reales.

> **Ideal para:** formación en ciberseguridad, demos técnicas, prototipado de canales cifrados y laboratorios de criptografía educativa.

---

## ✨ Características principales

| Categoría                  | Funcionalidad                                                                                                        |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| 🔑 **Gestión de claves**   | Creación, almacenamiento y rotación de claves César y XOR con persistencia en SQLite                                 |
| 📡 **Canal TCP seguro**    | Servidor TCP multihilo (`ThreadingMixIn`) para envío/recepción de mensajes cifrados en tiempo real                   |
| 🛡️ **Cifrados soportados** | **César** (desplazamiento Unicode) · **XOR** (Base64 + clave variable) · Arquitectura extensible vía `CipherFactory` |
| 📊 **Dashboard en vivo**   | KPIs en tiempo real · Tablas de últimos mensajes y auditorías · Auto-refresh cada 4 s                                |
| 🔍 **Auditoría completa**  | Registro de cada operación de descifrado con timestamp, canal y resultado verificado                                 |
| 🌙 **Dark mode**           | Cambio de tema claro/oscuro con persistencia en `localStorage`                                                       |
| 📦 **Export / Import**     | Exportación e importación de datos completos en JSON para backup o migración                                         |
| 🎲 **Seed de datos**       | Generación instantánea de 5 mensajes de prueba para demos rápidas                                                    |
| 🔎 **Búsqueda en vivo**    | Filtrado instantáneo sobre mensajes y auditorías sin recargar                                                        |
| 📱 **Responsive**          | Diseño adaptativo para escritorio, tablet y móvil                                                                    |

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────┐
│                    FRONTEND (SPA)                    │
│  ┌──────────┬──────────┬──────────┬────────────────┐ │
│  │Dashboard │  Claves  │  Enviar  │ Mensajes/Audit │ │
│  └──────────┴──────────┴──────────┴────────────────┘ │
│            app.js · styles.css · Dark Mode           │
└──────────────────────┬──────────────────────────────┘
                       │  REST API (JSON)
┌──────────────────────▼──────────────────────────────┐
│                   FLASK :5080                        │
│  CipherFactory ──▶ CaesarCipher / XorCipher         │
│  KeyManager ──▶ SQLite (keys_store)                  │
│  MessageStore ──▶ SQLite (messages + decrypt_audit)  │
└──────────────────────┬──────────────────────────────┘
                       │  TCP Socket :5095
┌──────────────────────▼──────────────────────────────┐
│           THREADED TCP SERVER (multihilo)            │
│  SecureTCPHandler ──▶ descifrado + respuesta JSON   │
└─────────────────────────────────────────────────────┘
```

---

## 📡 API REST

| Método | Endpoint                | Descripción                            |
| ------ | ----------------------- | -------------------------------------- |
| `GET`  | `/api/keys`             | Listar todas las claves registradas    |
| `POST` | `/api/keys`             | Crear nueva clave (César o XOR)        |
| `POST` | `/api/messages/send`    | Cifrar y enviar un mensaje             |
| `POST` | `/api/messages/decrypt` | Descifrar un mensaje existente         |
| `GET`  | `/api/messages`         | Obtener historial completo de mensajes |
| `GET`  | `/api/stats`            | KPIs en tiempo real del sistema        |

---

## 🛠️ Mejoras v2 implementadas

| #   | Mejora                        | Detalle                                                       |
| --- | ----------------------------- | ------------------------------------------------------------- |
| 1   | 🌙 Dark mode con persistencia | Toggle en toolbar, preferencia guardada en `localStorage`     |
| 2   | 🔔 Sistema de toasts          | Notificaciones con 4 tonos: éxito, error, warning, info       |
| 3   | ⚠️ Diálogo de confirmación    | `nousConfirm()` basado en Promises para acciones destructivas |
| 4   | 📊 Dashboard con KPIs         | Métricas en vivo: claves, mensajes HTTP/TCP, descifrados      |
| 5   | 📡 Status dot                 | Indicador de salud del backend con heartbeat automático       |
| 6   | 🏷️ Badges semánticos          | Etiquetas de color para canales (HTTP/TCP) y algoritmos       |
| 7   | 🔢 Contador de caracteres     | Feedback en tiempo real al redactar mensajes                  |
| 8   | 📤 Exportar JSON              | Backup completo de claves + mensajes + auditorías             |
| 9   | 📥 Importar JSON              | Restauración desde archivo con validación de estructura       |
| 10  | 🎲 Seed de datos              | 5 mensajes de demostración inyectados automáticamente         |
| 11  | 🔎 Búsqueda en vivo           | Filtro instantáneo en tablas de mensajes y auditorías         |
| 12  | 📱 Responsive layout          | Breakpoints a 1100 px y 700 px                                |
| 13  | 🫙 Empty states               | Mensajes informativos cuando las tablas están vacías          |
| 14  | ♻️ Auto-refresh               | Refresco automático cada 4 segundos vía `setInterval`         |

---

## ⚡ Inicio rápido

```bash
# 1 · Clonar el repositorio
git clone https://github.com/luisrocedev/Crypto-Channel-Lab.git
cd Crypto-Channel-Lab

# 2 · Instalar dependencias
pip install -r requirements.txt

# 3 · Arrancar la plataforma
python app.py
# ─▸ HTTP en http://localhost:5080
# ─▸ TCP en :5095

# 4 · (Opcional) Probar canal TCP
python tcp_secure_client.py
```

> **Puertos configurables** mediante variables de entorno: `CRYPTO_HTTP_PORT` y `CRYPTO_TCP_PORT`.

---

## 📂 Estructura del proyecto

```
Crypto-Channel-Lab/
├── app.py                        # Backend Flask + TCP Server + Ciphers
├── demo_simple.py                # Lanzador rápido
├── tcp_secure_client.py          # Cliente TCP de prueba
├── requirements.txt              # Dependencias Python
├── templates/
│   └── index.html                # SPA con 5 tabs + toolbar + dark mode
├── static/
│   ├── app.js                    # Lógica frontend completa (v2)
│   └── styles.css                # Estilos con design tokens + dark mode
└── docs/
    └── Actividad_Fundamentos_Encriptacion_53945291X.md
```

---

## 🧪 Tecnologías

| Capa         | Stack                                                                   |
| ------------ | ----------------------------------------------------------------------- |
| **Backend**  | Python 3.12 · Flask 3.x · SQLite 3 · `socketserver.ThreadingMixIn`      |
| **Frontend** | HTML5 · CSS3 (custom properties) · JavaScript ES2022 (vanilla)          |
| **Cifrado**  | César (Unicode shift) · XOR (Base64 + clave) · CipherFactory extensible |
| **Red**      | TCP multihilo con protocolo JSON `{action, key_name, text}`             |

---

## 👤 Autor

**Luis Rodríguez Cedeño** — DAM2 · Actividad PSP-004  
[github.com/luisrocedev](https://github.com/luisrocedev)

---

<p align="center"><em>Crypto Channel Lab — Cifrado aplicado, canal seguro, control total.</em></p>
