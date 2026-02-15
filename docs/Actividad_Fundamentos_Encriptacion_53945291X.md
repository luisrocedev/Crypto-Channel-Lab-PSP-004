# Actividad 004 · Fundamentos de encriptación

**Módulo:** Programación de servicios y procesos  
**Alumno:** Luis Rodríguez (53945291X)  
**Fecha:** 15/02/2026

## 1. Base del proyecto (referencia de clase)

El desarrollo toma como referencia los ejemplos de clase de encriptación vistos en:

- `005-Utilización de técnicas de programación segura/007-Encriptación de información/101-Ejercicios/005-metodos de una clase.php`
- `.../006-encriptar mysql.php`
- `.../008-ahora encripto.php`

Punto de partida aplicado:

- Modelo por **clase** con métodos `encriptar()` y `desencriptar()`.
- Cifrado básico de sustitución y guardado de mensajes en base de datos.

## 2. Cambios funcionales de calado implementados

Se amplía de ejercicio simple a un sistema completo de canal seguro:

1. **Arquitectura OOP ampliada de cifrado**
   - `CaesarCipher` (desplazamiento configurable)
   - `XorCipher` (secreto + codificación base64)
   - `CipherFactory` para selección dinámica por clave.

2. **Canal protegido entre dos puntos por dos vías**
   - API HTTP (`/api/messages/send`)
   - Servidor TCP dedicado para recepción de paquetes cifrados.

3. **Persistencia avanzada (SQLite)**
   - `keys_store`: claves y configuración criptográfica.
   - `messages`: trazas completas de mensajes cifrados.
   - `decrypt_audit`: auditoría de operaciones de descifrado.

4. **Trazabilidad y control de seguridad**
   - Registro de actor que descifra.
   - Preview del resultado y marcas temporales.
   - Estadísticas por algoritmo y volumen de operaciones.

## 3. Cambios visuales de calado implementados

Se sustituye la interfaz básica por un **dashboard operativo**:

- Tarjetas KPI de actividad (`total`, `caesar`, `xor`, `descifrados`).
- Formularios separados para:
  - alta de clave criptográfica,
  - envío de mensaje cifrado.
- Tabla principal de mensajes con acción de descifrado por registro.
- Tabla de auditoría de descifrado en tiempo real.
- Diseño responsive y jerarquía visual consistente.

## 4. Cumplimiento de requisitos de la actividad

Se cumple la rúbrica indicada:

- Basado en ejemplo de clase, no proyecto desde cero improvisado.
- Cambios funcionales de envergadura (múltiples cifrados, doble canal, auditoría, estadísticas).
- Cambios visuales de envergadura (dashboard completo frente a formulario simple).
- Persistencia y modelo de datos claramente evolucionados.

## 5. Estructura de entrega

Repositorio independiente de la actividad:

- `app.py`
- `templates/index.html`
- `static/app.js`
- `static/styles.css`
- `tcp_secure_client.py`
- `requirements.txt`
- `README.md`
- `docs/Actividad_Fundamentos_Encriptacion_53945291X.md`

## 6. Ejecución rápida

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

- Panel: `http://127.0.0.1:5080`
- Canal TCP: `127.0.0.1:5095`
