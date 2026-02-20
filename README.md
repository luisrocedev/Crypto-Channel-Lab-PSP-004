# Crypto Channel Lab

![Python](https://img.shields.io/badge/Python-3.13-3776ab?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000?logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-3-003b57?logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

**Sistema de comunicación cifrada** con múltiples algoritmos (César · XOR), doble canal HTTP + TCP, persistencia SQLite y auditoría completa de descifrado.

---

## Características principales

| Categoría | Detalle |
|-----------|---------|
| **Cifrado César** | Desplazamiento configurable (1-25) sobre Unicode |
| **Cifrado XOR** | Secreto + codificación Base64 |
| **Doble canal** | API REST HTTP y servidor TCP dedicado (multihilo) |
| **Gestión de claves** | CRUD completo con `keys_store` en SQLite |
| **Auditoría** | Tabla `decrypt_audit` con actor, timestamp y preview |
| **Dashboard v2** | 5 pestañas, dark mode, KPIs, toasts, confirm modal |
| **Trazabilidad** | Cada mensaje cifrado queda registrado con canal, clave y payload |

## Arquitectura

```
┌──────────────────────────────────────────────┐
│  Flask HTTP  (:5080)                         │
│  /api/keys · /api/messages/send · /api/stats │
├──────────────────────────────────────────────┤
│  TCP Server  (:5095)  — ThreadingMixIn       │
├──────────────────────────────────────────────┤
│  CaesarCipher · XorCipher · CipherFactory    │
├──────────────────────────────────────────────┤
│  SQLite (secure_channel.sqlite3)             │
│  keys_store · messages · decrypt_audit       │
└──────────────────────────────────────────────┘
```

## API REST

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET`  | `/api/keys` | Listar claves registradas |
| `POST` | `/api/keys` | Crear nueva clave (césar / xor) |
| `POST` | `/api/messages/send` | Cifrar y enviar mensaje vía HTTP |
| `POST` | `/api/messages/decrypt` | Descifrar mensaje por ID |
| `GET`  | `/api/messages` | Listar mensajes cifrados |
| `GET`  | `/api/stats` | Estadísticas (total, por cifrado, runtime) |

## 14 Mejoras v2 — Frontend

| # | Mejora | Implementación |
|---|--------|----------------|
| 1 | Design Tokens | Variables CSS en `:root` para colores, radios, sombras |
| 2 | Dark mode | Toggle 🌙/☀️ con `localStorage` y `prefers-color-scheme` |
| 3 | Tabs | 5 pestañas: Dashboard · Claves · Enviar · Mensajes · Auditoría |
| 4 | Panel Dashboard | KPIs + mini-tablas de últimos 5 mensajes y auditorías |
| 5 | KPIs con borde color | `border-left` 4 px semántico + hover `translateY(-2px)` |
| 6 | Toasts | 4 tonos (ok/error/info/warning), `slideDown` + auto-dismiss |
| 7 | nousConfirm | Modal con overlay blur, animación `scaleIn`, `async/await` |
| 8 | Export / Import JSON | Descarga `.json` con mensajes + auditorías; reimportación |
| 9 | Seed data | 5 mensajes demo con diferentes emisores y cifrados |
| 10 | Buscador en tiempo real | Filtro client-side sobre tabla de mensajes |
| 11 | Badges de canal/cifrado | HTTP verde, TCP cian, César violeta, XOR ámbar |
| 12 | Contador de caracteres | Indicador `0 / 600` dinámico bajo el textarea |
| 13 | Empty states | Placeholders con icono cuando no hay datos |
| 14 | Responsive | Breakpoints 1 100 px / 700 px para KPIs, columnas, toolbar |

## Ejecución

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

| Servicio | URL |
|----------|-----|
| Dashboard HTTP | `http://127.0.0.1:5080` |
| Canal TCP cifrado | `127.0.0.1:5095` |

## Prueba del canal TCP

Con la app en ejecución:

```bash
python tcp_secure_client.py
```

El mensaje se cifrará y quedará registrado en el dashboard.

## Estructura

```
Crypto-Channel-Lab/
├── app.py                 # Backend Flask + TCP + cifrado + SQLite
├── demo_simple.py         # Lanzador rápido
├── tcp_secure_client.py   # Cliente TCP de prueba
├── requirements.txt       # Flask
├── templates/
│   └── index.html         # Dashboard v2 (5 tabs, dark mode, toasts)
├── static/
│   ├── app.js             # Lógica frontend v2
│   └── styles.css         # Diseño v2 con tokens + responsive
└── docs/
    └── Actividad_Fundamentos_Encriptacion_53945291X.md
```

## Autor

**Luis Rodríguez Cedeño** — DAM2 · Programación de servicios y procesos

---

> Proyecto académico con fines educativos — DAM2 PSP 2025-2026
