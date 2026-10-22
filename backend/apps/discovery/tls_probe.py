import ipaddress
import re
import shutil
import socket
import ssl
import subprocess
from datetime import timezone as dt_timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from django.conf import settings

from .network_utils import public_url

# Python's ssl module cannot report the negotiated key-exchange group, which is
# the one thing that shows whether a server already uses hybrid PQC key
# establishment. An OpenSSL >= 3.5 CLI can, so it is used when available.
_GROUP_LINE = re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)", re.I)
_TEMP_KEY_LINE = re.compile(r"(?:Peer|Server) Temp Key:\s*(.+)", re.I)


def parse_group(output):
    """Extract the group from `openssl s_client -brief` output (TLS 1.3 and 1.2 forms)."""
    match = _GROUP_LINE.search(output)
    if match:
        return match.group(1)
    match = _TEMP_KEY_LINE.search(output)
    if not match:
        return None
    parts = [p.strip() for p in match.group(1).split(",")]
    if parts[0].upper() == "ECDH" and len(parts) > 1:
        return parts[1]                       # "ECDH, prime256v1, 256 bits"
    if parts[0].upper() == "DH" and len(parts) > 1:
        bits = parts[1].split()[0]
        return f"FFDHE{bits}" if bits.isdigit() else "DH"  # "DH, 2048 bits"
    return parts[0]                           # "X25519, 253 bits"
_GROUP_NAMES = {
    "PRIME256V1": "ECDH-P256", "SECP256R1": "ECDH-P256", "SECP384R1": "ECDH-P384", "SECP521R1": "ECDH-P521",
    "X25519": "X25519", "X448": "X448", "ECDH": "ECDH (curve not reported)",
    "FFDHE2048": "DH-2048", "FFDHE3072": "DH-3072", "FFDHE4096": "DH-4096", "DH": "DH (group not reported)",
}
LEGACY_VERSIONS = (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1))


def _connect_host(address):
    return f"[{address}]" if ipaddress.ip_address(address).version == 6 else address


def negotiated_group(address, port, host, timeout=10):
    """Return the key-exchange group the server picks when offered OpenSSL's
    default list (which leads with X25519MLKEM768 on OpenSSL 3.5+), or None."""
    binary = shutil.which(getattr(settings, "OPENSSL_BIN", "openssl"))
    if not binary:
        return None
    command = [binary, "s_client", "-connect", f"{_connect_host(address)}:{port}", "-servername", host, "-brief"]
    try:
        proc = subprocess.run(command, input="", capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_group(f"{proc.stdout}\n{proc.stderr}")


def group_asset_name(group):
    return _GROUP_NAMES.get(group.upper(), group)


def key_exchange_from_suite(protocol, cipher_suite):
    """Fallback when the group is not reported: TLS 1.2 suites name the key exchange."""
    suite = (cipher_suite or "").upper()
    if protocol == "TLS 1.3":
        return "TLS 1.3 key exchange (group not reported)"
    if suite.startswith(("ECDHE", "TLS_ECDHE")):
        return "ECDH (curve not reported)"
    if suite.startswith(("DHE", "EDH", "TLS_DHE")):
        return "DH (group not reported)"
    return "RSA (key transport)"


def supports_version(address, port, host, version, timeout=5):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")  # legacy versions are refused at the default level
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True
    except (OSError, ssl.SSLError, ValueError):
        return False


def _name(parts):
    return ", ".join(f"{item.oid._name or item.oid.dotted_string}={item.value}" for item in parts)


def _cipher_asset(cipher_name):
    upper = cipher_name.upper()
    for mode in ("GCM", "CCM", "CBC", "CTR"):
        if f"AES_128_{mode}" in upper or f"AES128-{mode}" in upper:
            return f"AES-128-{mode}"
        if f"AES_256_{mode}" in upper or f"AES256-{mode}" in upper:
            return f"AES-256-{mode}"
    if "CHACHA20" in upper:
        return "ChaCha20-Poly1305"
    return cipher_name


def probe_tls(target, timeout=8):
    parsed, addresses = public_url(target, schemes=("https", "http"))
    host = parsed.hostname
    port = parsed.port or 443
    verified = True
    verification_error = ""
    context = ssl.create_default_context()
    try:
        raw = socket.create_connection((addresses[0], port), timeout=timeout)
        tls = context.wrap_socket(raw, server_hostname=host)
    except ssl.SSLCertVerificationError as exc:
        verified = False
        verification_error = str(exc)
        context = ssl._create_unverified_context()
        raw = socket.create_connection((addresses[0], port), timeout=timeout)
        tls = context.wrap_socket(raw, server_hostname=host)
    with tls:
        version = tls.version()
        cipher = tls.cipher()
        der = tls.getpeercert(binary_form=True)

    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_algorithm, key_size = "RSA", pub.key_size
        key_asset = f"RSA-{key_size}"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_size = pub.key_size
        key_algorithm = "EC"
        key_asset = f"ECDSA-P{key_size}"
    elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_algorithm = key_asset = "Ed25519" if isinstance(pub, ed25519.Ed25519PublicKey) else "Ed448"
        key_size = 256 if key_asset == "Ed25519" else 448
    else:
        key_algorithm = type(pub).__name__
        key_size = getattr(pub, "key_size", None)
        key_asset = key_algorithm

    signature = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
    sans = []
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    protocol = version.replace("TLSv", "TLS ")
    cipher_suite = cipher[0] if cipher else ""
    group = negotiated_group(addresses[0], port, host)
    supported = [protocol] + [label for label, v in LEGACY_VERSIONS
                              if label != protocol and supports_version(addresses[0], port, host, v)]
    return {
        "target": target,
        "host": host,
        "port": port,
        "resolved_address": addresses[0],
        "verified": verified,
        "verification_error": verification_error,
        "protocol": protocol,
        "supported_versions": supported,
        "key_exchange": {
            "group": group,
            "algorithm": group_asset_name(group) if group else key_exchange_from_suite(protocol, cipher_suite),
            "evidence": "openssl_s_client" if group else "cipher_suite",
        },
        "cipher_suite": cipher_suite,
        "cipher_bits": cipher[2] if cipher else None,
        "cipher_algorithm": _cipher_asset(cipher[0]) if cipher else "",
        "certificate": {
            "subject": _name(cert.subject),
            "issuer": _name(cert.issuer),
            "serial_number": str(cert.serial_number),
            "not_before": cert.not_valid_before_utc.astimezone(dt_timezone.utc),
            "not_after": cert.not_valid_after_utc.astimezone(dt_timezone.utc),
            "key_algorithm": key_algorithm,
            "key_size": key_size,
            "key_asset": key_asset,
            "signature_algorithm": signature,
            "san": sans,
            "is_self_signed": cert.issuer == cert.subject,
        },
    }
