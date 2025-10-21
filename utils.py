# utils.py
import socket
from typing import Tuple

def resolve_host(host: str) -> Tuple[str, str]:
    """
    Resolve host to (host, ip). Raises socket.gaierror on failure.
    """
    ip = socket.gethostbyname(host)
    return host, ip

def format_results(results):
    lines = []
    for r in results:
        if r.open:
            service_info = f" ({r.service})" if r.service and r.service != "Unknown" else ""
            banner_text = f" | banner: {r.banner}" if r.banner else ""
            lines.append(f"[OPEN]  Port {r.port}/{r.protocol.upper()}{service_info}{banner_text}")
        else:
            lines.append(f"[CLOSED] Port {r.port}/{r.protocol.upper()}")
    return "\n".join(lines)
