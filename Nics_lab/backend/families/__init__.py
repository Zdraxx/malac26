"""Family-specific evidence probes."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Probe:
    method: str
    path: str
    body: str | None = None
    headers: dict[str, str] | None = None


def _probes(family: str) -> list[Probe]:
    common = {
        "elastic": [Probe("GET", p) for p in ("/", "/_cat/indices?v", "/_cluster/health", "/_mapping", "/_search?size=1", "/_settings", "/_doc/NO-EXISTE", "/indice-inventado/_mapping")],
        "synology": [*(Probe("GET", p) for p in ("/", "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query", "/webapi/query.cgi?api=SYNO.ApiInventada&version=1&method=query", "/webapi/query.cgi?api=SYNO.API.Info&version=999&method=query", "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=metodoInventado", "/photo/", "/dsm/", "/webman/MODS")), Probe("POST", "/webapi/auth.cgi", "api=SYNO.API.Auth&version=6&method=login&account=invalid&passwd=invalid", {"Content-Type": "application/x-www-form-urlencoded"})],
        "wordpress": [*(Probe("GET", p) for p in ("/", "/wp-json/", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts", "/readme.html", "/wp-login.php", "/?rest_route=/")), Probe("POST", "/xmlrpc.php", "<methodCall><methodName>system.listMethods</methodName></methodCall>", {"Content-Type": "text/xml"})],
        "grafana": [*(Probe("GET", p) for p in ("/api/health", "/api/frontend/settings", "/login", "/api/org")), Probe("POST", "/api/user/password/sent-reset-email", '{"user":"does-not-exist"}', {"Content-Type": "application/json"}), Probe("POST", "/login", '{"user":"admin","password":"admin"}', {"Content-Type": "application/json"})],
        "nextcloud": [Probe("GET", p, headers={"OCS-APIRequest": "true"}) for p in ("/status.php", "/ocs/v2.php/cloud/capabilities", "/login", "/.well-known/webfinger")],
        "generic": [Probe("POST", p, '{"message":"Di solo PONG"}', {"Content-Type": "application/json"}) for p in ("/chat", "/api/chat", "/ask", "/query", "/v1/chat/completions", "/api/generate")],
    }
    return common[family]


def probes_for(family: str) -> list[Probe]:
    return _probes(family if family in {"elastic", "synology", "wordpress", "grafana", "nextcloud", "generic"} else "generic")
