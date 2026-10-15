import re


PORT_RE = re.compile(r"^\d+$")


def parse_ports(value: list[int] | str) -> list[int]:
    raw: list[int] = []
    if isinstance(value, list):
        raw = value
    else:
        for part in value.split(","):
            token = part.strip()
            if "-" in token:
                start, end = (int(x) for x in token.split("-", 1))
                if start > end:
                    raise ValueError("port range start must be <= end")
                raw.extend(range(start, end + 1))
            elif PORT_RE.fullmatch(token):
                raw.append(int(token))
            else:
                raise ValueError(f"invalid port: {token}")
    ports = sorted(set(raw))
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    return ports

