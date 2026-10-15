# Recon CTF

Backend local y orientado a evidencias para reconocimiento durante un CTF.
La aplicación conserva respuestas crudas, latencias, headers, pistas y
observaciones para revisión humana; no decide si un servicio es real,
honeypot o IA.

## Instalación y ejecución

Requiere Python 3.11+:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
uvicorn backend.main:app --reload
```

La interfaz queda en `http://127.0.0.1:8000/` y la documentación de la API en
`http://127.0.0.1:8000/docs`. SQLite se crea como `recon.db` y los
recursos descargados se reservan para `loot/<puerto>/`.

## Ejemplo

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H 'content-type: application/json' \
  -d '{"target":"127.0.0.1","ports":"8000,8080-8082","concurrency":10}'
curl http://127.0.0.1:8000/api/scan/1
curl -X POST http://127.0.0.1:8000/api/collect/8000
curl http://127.0.0.1:8000/api/port/8000/report
```

`POST /api/scan` devuelve inmediatamente un id. El progreso se consulta con
`GET /api/scan/{id}` o por `ws://127.0.0.1:8000/ws/scan/{id}`. Todos los
requests, respuestas y errores de probes se persisten.

## Añadir una familia

1. Añade el nombre y sus sondas en `backend/families/__init__.py`, usando
   `Probe(method, path, body, headers)`.
2. Añade un módulo `backend/families/<nombre>.py` con un docstring que explique
   qué superficie prueba y por qué.
3. Amplía `detect_family` en `backend/collector.py` con una señal observable.
4. Añade una prueba en `tests/test_families.py`.

Las sondas deben usar `httpx` a través del contrato existente, respetar el
timeout de 3 segundos y no ejecutar comandos del sistema.

## Informe Markdown y exportación

- `GET /api/port/{port}/report` devuelve el informe Markdown del último registro
  de ese puerto.
- `GET /api/export` devuelve el JSON completo, incluidos cuerpos crudos,
  headers, clues y observations.
