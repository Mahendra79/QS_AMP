"""Static discovery of cryptographic usage in a source tree (regex-based; heuristic).

Findings are *evidence of usage* - they need human confirmation. The scanner
never executes any scanned file.
"""
import json
import os
import re
from pathlib import Path

TEXT_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".rs",
            ".swift", ".scala", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".xml", ".properties", ".env", ".toml",
            ".sh", ".tf", ".gradle", ".txt", ".md", ".pem", ".crt", ".cer", ".key", ".pub"}
MAX_FILE_BYTES = 1_500_000

# (regex, algorithm name, purpose, function, library hint)
PATTERNS = [
    (r"RSA[-_/ ]?(1024|2048|3072|4096)|rsa\.generate_private_key|KeyPairGenerator\.getInstance\(\"RSA\"\)|generateKeyPair\(['\"]rsa", "RSA", "key_exchange", "keygen", ""),
    (r"\b(RS256|RS384|RS512|PS256|SHA\d+withRSA|RSASSA-PKCS1)", "RSA", "digital_signature", "sign", ""),
    (r"\b(ECDSA|ES256|ES384|secp256r1|prime256v1|SHA256withECDSA)\b", "ECDSA-P256", "digital_signature", "sign", ""),
    (r"\b(Ed25519|Ed448)\b", "EdDSA", "digital_signature", "sign", ""),
    # Hybrid groups are matched before plain ECDH so X25519MLKEM768 is not reported as X25519.
    (r"\b(X25519|SecP256r1|SecP384r1)[-_]?(MLKEM|Kyber)[-_]?(768|1024)\b", "HYBRID", "key_exchange", "encapsulate", "pqc"),
    (r"\b(ECDH|ECDHE|X25519(?![-_]?(?:MLKEM|Kyber))|secp256k1|ecdh\.)", "ECDH-P256", "key_exchange", "key-agree", ""),
    (r"AES[-_/ ]?(128|192|256)[-_/ ]?(GCM|CBC|CTR|ECB|CCM)?|Cipher\.getInstance\(\"AES", "AES", "symmetric_encryption", "encrypt", ""),
    (r"\b(3DES|DESede|TripleDES|des3)\b", "3DES", "symmetric_encryption", "encrypt", ""),
    (r"Cipher\.getInstance\(\"DES[\"/]|\bDES[-_/](?:CBC|ECB)\b|\bDES\.new\(", "DES", "symmetric_encryption", "encrypt", ""),
    (r"\b(RC4|ARCFOUR)\b|\bARC4\.new\(", "RC4", "symmetric_encryption", "encrypt", ""),
    (r"hashlib\.sha1|MessageDigest\.getInstance\(\"SHA-?1\"\)|createHash\(['\"]sha1|\bSHA-?1\b|sha1sum", "SHA-1", "hashing", "digest", ""),
    (r"hashlib\.sha256|SHA-?256|createHash\(['\"]sha256", "SHA-256", "hashing", "digest", ""),
    (r"hashlib\.md5|createHash\(['\"]md5|MessageDigest\.getInstance\(\"MD5\"\)|\bMD5\b", "MD5", "hashing", "digest", ""),
    (r"TLSv?1[._]?[012]\b|ssl\.PROTOCOL_TLSv1|minVersion.*TLSv1(\.[01])?\b|SSLv3", "TLS 1.0", "transport_security", "handshake", ""),
    (r"TLSv?1[._]?2\b|TLS_VERSION_1_2", "TLS 1.2", "transport_security", "handshake", ""),
    (r"TLSv?1[._]?3\b|TLS_VERSION_1_3", "TLS 1.3", "transport_security", "handshake", ""),
    (r"\b(?:ML[-_]?KEM(?:[-_](512|768|1024))?|Kyber(?:[-_](512|768|1024))?)\b", "ML-KEM", "key_exchange", "encapsulate", "pqc"),
    (r"\b(?:ML[-_]?DSA(?:[-_](44|65|87))?|Dilithium(?:[-_](2|3|5))?)\b", "ML-DSA", "digital_signature", "sign", "pqc"),
    (r"\b(?:SLH[-_]?DSA|SPHINCS\+?)\b", "SLH-DSA", "digital_signature", "sign", "pqc"),
]
COMPILED = [(re.compile(p, re.I), *rest) for p, *rest in PATTERNS]
PEM_BEGIN = re.compile(r"-----BEGIN ((?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY|CERTIFICATE)-----")

CRYPTO_LIBS = {
    "python": {"cryptography": "cryptography", "pycryptodome": "PyCryptodome", "pycrypto": "PyCrypto (unmaintained)",
               "pyopenssl": "pyOpenSSL", "pyjwt": "PyJWT", "paramiko": "paramiko", "pynacl": "PyNaCl", "oqs": "liboqs-python"},
    "node": {"crypto-js": "crypto-js", "node-forge": "node-forge", "jsonwebtoken": "jsonwebtoken", "bcrypt": "bcrypt",
             "jose": "jose", "tweetnacl": "tweetnacl", "node-rsa": "node-rsa", "@noble/post-quantum": "noble-post-quantum"},
    "java": {"bcprov": "BouncyCastle", "bcpkix": "BouncyCastle PKIX", "nimbus-jose-jwt": "Nimbus JOSE+JWT", "jjwt": "jjwt"},
    "go": {"golang.org/x/crypto": "golang.org/x/crypto", "github.com/cloudflare/circl": "CIRCL (PQC)"},
}


def scan_tree(root, app_name="", max_findings=2000):
    """Return dict(files, findings, libraries, certificates, keys, protocols)."""
    root = Path(root)
    files = 0
    findings, libs, certs, keys = [], {}, [], []
    seen = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__", "vendor", ".venv")]
        for fn in filenames:
            p = Path(dirpath) / fn
            rel = str(p.relative_to(root)).replace("\\", "/")
            ext = p.suffix.lower()
            base = fn.lower()
            files += 1
            if base in ("requirements.txt", "package.json", "pom.xml", "go.mod", "build.gradle", "pyproject.toml"):
                _deps(p, base, rel, libs)
            if ext not in TEXT_EXT and base not in ("dockerfile",):
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            # Every PEM block counts: bundles and chains hold several certificates per file.
            for m in PEM_BEGIN.finditer(text):
                if "PRIVATE KEY" in m.group(1):
                    keys.append({"file": rel, "type": m.group(1)})
                else:
                    end = text.find("-----END CERTIFICATE-----", m.start())
                    block_end = end + len("-----END CERTIFICATE-----") if end != -1 else m.start() + 6000
                    certs.append({"file": rel, "text": text[m.start():block_end]})
            if len(findings) >= max_findings:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if len(line) > 400:
                    continue
                for rx, alg, purpose, fn_, hint in COMPILED:
                    m = rx.search(line)
                    if not m:
                        continue
                    a = alg
                    if alg == "RSA" and m.group(1) and m.group(1).isdigit():
                        a = f"RSA-{m.group(1)}"
                    elif alg == "RSA":
                        a = "RSA (size unknown)"
                    elif alg == "AES":
                        a = _aes_name(m, line)
                    elif alg == "HYBRID":
                        a = f"{m.group(1)}MLKEM{m.group(3)}"
                    elif alg == "EdDSA":
                        a = m.group(1).title()
                    elif alg == "TLS 1.0":
                        a = "TLS 1.0" if re.search(r"1[._]?[01]\b|SSLv3", m.group(0)) else "TLS 1.2"
                    elif alg == "ML-KEM":
                        size = next((g for g in m.groups() if g), None)
                        a = f"ML-KEM-{size}" if size else "ML-KEM (parameter set unknown)"
                    elif alg == "ML-DSA":
                        size = next((g for g in m.groups() if g), None)
                        legacy = {"2": "44", "3": "65", "5": "87"}
                        a = f"ML-DSA-{legacy.get(size, size)}" if size else "ML-DSA (parameter set unknown)"
                    key = (a, rel, purpose)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({"algorithm": a, "purpose": purpose, "function": fn_, "file": rel,
                                     "line": lineno, "snippet": line.strip()[:160], "pqc": hint == "pqc"})
    return {"files": files, "findings": findings, "libraries": libs, "certificates": certs, "keys": keys}


_AES_MODE = re.compile(r"AES[-_/ ]?(?:(?:128|192|256)[-_/ ]?)?(GCM|CBC|CTR|ECB|CCM)", re.I)


def _aes_name(match, line):
    """Name an AES use from what is actually present. Size and mode are only
    included when observed - an unqualified AES reference is not assumed to be
    AES-256-GCM (Java's bare "AES" defaults to ECB)."""
    if re.search(r"getInstance\(\"AES\"\)", line):
        return "AES-ECB (Java default mode)"
    bits = match.group(1)
    mode_match = _AES_MODE.search(line)
    mode = match.group(2) or (mode_match.group(1) if mode_match else None)
    if bits and mode:
        return f"AES-{bits}-{mode.upper()}"
    if bits:
        return f"AES-{bits}"
    if mode:
        return f"AES-{mode.upper()} (key size unknown)"
    return "AES (key size unknown)"


def _deps(path, base, rel, libs):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    if base in ("requirements.txt", "pyproject.toml"):
        for name, label in CRYPTO_LIBS["python"].items():
            m = re.search(rf"^\s*{re.escape(name)}\s*(?:[=<>~!]+\s*([\w.]+))?", text, re.I | re.M)
            if m or (base == "pyproject.toml" and name in text.lower()):
                libs[label] = {"version": (m.group(1) if m and m.group(1) else ""), "language": "python", "file": rel}
    elif base == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, label in CRYPTO_LIBS["node"].items():
            if name in deps:
                libs[label] = {"version": str(deps[name]).lstrip("^~"), "language": "javascript", "file": rel}
    else:
        for name, label in {**CRYPTO_LIBS["java"], **CRYPTO_LIBS["go"]}.items():
            if name in text:
                libs[label] = {"version": "", "language": "java/go", "file": rel}
