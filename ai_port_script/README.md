# honeypot_survey

Herramienta de **reconocimiento inicial** para identificar servicios HTTP/HTTPS
en un entorno de CTF y separar a primera vista tres categorías:

- servicios reales
- honeypots simples (respuesta estática)
- posibles honeypots con IA (LLM detrás)

No clasifica automáticamente. **Recoge evidencia objetiva** (códigos HTTP,
latencias, variedad de respuestas y frases típicas de modelos de lenguaje)
y la presenta en una tabla para triaje manual.

---

## Motivación

En un CTF con servicios mezclados (reales + honeypots de varios tipos), el
primer paso es descartar páginas muertas y detectar comportamiento anómalo.
Un honeypot con IA se delata por tres cosas que esta herramienta mide:

1. **Latencia alta y variable** (500 ms – 5 s), porque hay un LLM generando.
2. **Respuestas distintas a preguntas idénticas o ambiguas**, porque el
   modelo no es determinista.
3. **Frases características de LLM** ("as a language model", "soy un
   modelo", "no puedo ayudarte", "system prompt"…).

Un honeypot simple, en cambio, se delata por lo contrario: **mismo cuerpo y
mismos headers a cualquier input**, latencia plana y códigos HTTP siempre
iguales.

---

## Requisitos

- Python 3.8+
- `requests`
- `urllib3`

```bash
pip install requests urllib3
