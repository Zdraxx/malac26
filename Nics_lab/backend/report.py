import json

from sqlalchemy.orm import Session

from .models import Port, RequestRecord


def port_markdown(port: Port) -> str:
    lines = [f"# Puerto {port.port}", "", f"- Estado: `{port.status}`", f"- Familia: `{port.family}`", f"- Sugerencia: `{port.suggested_label or 'sin sugerencia'}`", "", "## Observaciones"]
    for item in port.observations:
        lines += [f"### {item.tipo}", item.descripcion, f"- Evidencia: `{item.evidencia}`", f"- Sugerencia: {item.sugerencia}", ""]
    lines += ["## Requests"]
    for request in port.requests:
        lines.append(f"- `{request.method} {request.url}` -> `{request.status}` ({request.latency_ms:.2f} ms, {request.size} bytes)")
    lines += ["", "## Pistas"]
    for clue in port.clues:
        lines.append(f"- `{clue.tipo}`: {clue.valor} ({clue.source_url or ''})")
    return "\n".join(lines) + "\n"


def export_port(db: Session, port: Port) -> dict:
    return {
        "port": port.port,
        "status": port.status,
        "family": port.family,
        "suggested_label": port.suggested_label,
        "requests": [{"id": r.id, "method": r.method, "url": r.url, "status": r.status, "latency_ms": r.latency_ms, "size": r.size, "headers": json.loads(r.headers_json), "request_body": r.request_body, "response_body": r.response_body, "error": r.error} for r in port.requests],
        "clues": [{"tipo": c.tipo, "valor": c.valor, "source_url": c.source_url, "contexto": c.contexto} for c in port.clues],
        "observations": [{"tipo": o.tipo, "descripcion": o.descripcion, "evidencia": o.evidencia, "sugerencia": o.sugerencia} for o in port.observations],
    }

