import ipaddress
import socket
from urllib.parse import urlparse

from apps.organizations.errors import ServiceError


def public_url(value, *, schemes=("https",), default_scheme="https"):
    raw = (value or "").strip()
    if "://" not in raw:
        raw = f"{default_scheme}://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in schemes or not parsed.hostname:
        raise ServiceError("invalid_target", f"A public {'/'.join(schemes)} URL is required.")
    if parsed.username or parsed.password:
        raise ServiceError("invalid_target", "Credentials are not allowed in source URLs.")
    try:
        addresses = {row[4][0] for row in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ServiceError("target_unreachable", f"Could not resolve {parsed.hostname}.") from exc
    if not addresses:
        raise ServiceError("target_unreachable", f"Could not resolve {parsed.hostname}.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ServiceError("unsafe_target", "Private, local, reserved, and non-public targets are not allowed.")
    return parsed, sorted(addresses)
