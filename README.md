# Crypto Channel Lab (PSP · DAM2)

Proyecto final de Fundamentos de Encriptación basado en el patrón de clase (clase `Encriptador` + cifrado básico), evolucionado a una plataforma completa de comunicación protegida entre dos puntos.

## Mejoras funcionales de calado

- Implementación orientada a objetos de cifrado con clases:
  - `CaesarCipher`
  - `XorCipher`
  - `CipherFactory`
- Gestión de claves en base de datos (`keys_store`) para seleccionar algoritmo y parámetros.
- Canal protegido por **HTTP** y por **TCP socket**.
- Persistencia completa de mensajes cifrados en SQLite (`messages`).
- Auditoría de operaciones de descifrado (`decrypt_audit`).
- API REST para claves, envío cifrado, descifrado y estadísticas.

## Mejoras visuales

- Dashboard moderno con KPIs de cifrado.
- Gestión visual de claves y envío de mensajes.
- Tabla de trazabilidad de mensajes cifrados.
- Tabla de auditoría de descifrados para control operativo.

## Estructura

- `app.py`: backend Flask + TCP server + cifrado + SQLite.
- `templates/index.html`: panel de control.
- `static/app.js`: lógica cliente.
- `static/styles.css`: diseño visual.
- `tcp_secure_client.py`: cliente TCP para probar comunicación entre dos nodos.

## Ejecución

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Servicios por defecto:

- Panel HTTP: `http://127.0.0.1:5080`
- Canal TCP cifrado: `127.0.0.1:5095`

## Prueba del canal TCP

Con la app ejecutándose:

```bash
python tcp_secure_client.py
```

El mensaje se cifrará y quedará registrado en el dashboard.
