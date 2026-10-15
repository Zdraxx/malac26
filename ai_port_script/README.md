# honeypot_survey

Script de reconocimiento para CTF. Sondea puertos HTTP/HTTPS y ayuda a
distinguir entre **servicio real**, **honeypot simple** y **honeypot con IA**.

## Qué hace

Por cada puerto lanza 6 peticiones: baseline, query aleatoria, prompt
injection, jailbreak, pregunta de identidad y 404. Mide códigos HTTP,
latencia, número de cuerpos distintos y frases típicas de LLM.

Devuelve una tabla para triaje manual:

- `nBodies = 1` y todo 200 → honeypot simple
- Códigos coherentes (200/400/404/405) y `nBodies ≥ 3` → servicio real
- Frase de LLM + latencia > 1.5 s → honeypot con IA

## Para qué

Acelera el reconocimiento inicial. **No clasifica**, solo da evidencia
objetiva para que el analista decida.

## Uso

```bash
pip install requests urllib3
python3 honeypot_survey.py           # todos los puertos
python3 honeypot_survey.py -w 6      # más concurrencia
python3 honeypot_survey.py -p 20749,54181
