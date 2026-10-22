"""Benchmark abstraction layer.

BenchmarkRunner drives adapters through run_keygen / run_encapsulation /
run_decapsulation / run_sign / run_verify. Adapters (registered in ADAPTERS):

  LiboqsAdapter          measured, native liboqs via `oqs` (used automatically if installed)
  CryptographyAdapter    measured, classical algorithms via pyca/cryptography (OpenSSL)
  PurePythonPQCAdapter   measured, ML-KEM/ML-DSA via kyber-py / dilithium-py.
                         These are pure-Python *educational reference* implementations:
                         timings are real for this environment but NOT representative
                         of optimized native code. Results carry that caveat.
  DemoAdapter            synthetic, deterministic values labelled "demo". Never real.

Future integrations (OpenSSL 3.5 providers, PQClean, ...) only need to subclass
BaseAdapter and be appended to ADAPTERS.
"""
import hashlib
import platform
import statistics
import threading
import time
import tracemalloc
from datetime import timedelta

from django.conf import settings
from django.db import close_old_connections, transaction
from django.utils import timezone

from apps.organizations.errors import ServiceError

from .models import BenchmarkResult, BenchmarkRun

OPERATIONS = ["keygen", "encapsulation", "decapsulation", "sign", "verify"]
OP_METHOD = {"keygen": "run_keygen", "encapsulation": "run_encapsulation", "decapsulation": "run_decapsulation",
             "sign": "run_sign", "verify": "run_verify"}

KEM_ALGS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
DSA_ALGS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
SLH_ALGS = ["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s"]
CLASSICAL_ALGS = ["RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "ECDH-P256", "ECDH-P384", "X25519"]
ALL_ALGS = CLASSICAL_ALGS + KEM_ALGS + DSA_ALGS + SLH_ALGS


def supported_operations(alg):
    if alg.startswith("RSA"):
        return ["keygen", "encapsulation", "decapsulation", "sign", "verify"]
    if alg.startswith(("ECDSA", "ML-DSA", "SLH-DSA")):
        return ["keygen", "sign", "verify"]
    return ["keygen", "encapsulation", "decapsulation"]  # ECDH, X25519, ML-KEM


class BaseAdapter:
    name = "base"
    data_source = "measured"
    library = ""
    compiler = ""
    caveat = ""

    def is_available(self):
        return True

    def supports(self, alg):
        return False

    def max_iterations(self, alg, op):
        return 200

    def setup(self, alg):
        return {}

    # Each run_* performs exactly one operation.
    def run_keygen(self, ctx): raise NotImplementedError
    def run_encapsulation(self, ctx): raise NotImplementedError
    def run_decapsulation(self, ctx): raise NotImplementedError
    def run_sign(self, ctx): raise NotImplementedError
    def run_verify(self, ctx): raise NotImplementedError

    def measure(self, alg, op, iterations, ctx):
        fn = getattr(self, OP_METHOD[op])
        fn(ctx)  # warm-up
        samples = []
        for _ in range(iterations):
            t = time.perf_counter()
            fn(ctx)
            samples.append((time.perf_counter() - t) * 1000)
        mem = None
        tracemalloc.start()
        try:
            fn(ctx)
            mem = tracemalloc.get_traced_memory()[1] / 1024
        finally:
            tracemalloc.stop()
        return samples, mem


class CryptographyAdapter(BaseAdapter):
    name = "cryptography"
    caveat = "Memory is Python-heap peak only (tracemalloc); native OpenSSL allocations are not included."

    def __init__(self):
        import cryptography
        from cryptography.hazmat.backends.openssl.backend import backend
        self.library = f"pyca/cryptography {cryptography.__version__} (OpenSSL {backend.openssl_version_text()})"
        self.compiler = "native OpenSSL build (compiler not reported)"

    def supports(self, alg):
        return alg in CLASSICAL_ALGS

    def max_iterations(self, alg, op):
        if op == "keygen" and alg.startswith("RSA"):
            return {"RSA-2048": 15, "RSA-3072": 6, "RSA-4096": 3}[alg]
        return 200

    def setup(self, alg):
        from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519
        ctx = {"alg": alg}
        if alg.startswith("RSA"):
            ctx["priv"] = rsa.generate_private_key(65537, int(alg.split("-")[1]))
            ctx["pub"] = ctx["priv"].public_key()
            ctx["msg"] = b"qsamp benchmark message" * 2
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            ctx["oaep"] = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ctx["pss"] = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
            ctx["ct"] = ctx["pub"].encrypt(b"k" * 32, ctx["oaep"])
            ctx["sig"] = ctx["priv"].sign(ctx["msg"], ctx["pss"], hashes.SHA256())
        elif alg.startswith("ECDSA"):
            ctx["curve"] = ec.SECP256R1() if "256" in alg else ec.SECP384R1()
            ctx["priv"] = ec.generate_private_key(ctx["curve"])
            ctx["pub"] = ctx["priv"].public_key()
            ctx["msg"] = b"qsamp benchmark message" * 2
            from cryptography.hazmat.primitives import hashes
            ctx["hash"] = hashes.SHA256() if "256" in alg else hashes.SHA384()
            ctx["sig"] = ctx["priv"].sign(ctx["msg"], ec.ECDSA(ctx["hash"]))
        elif alg == "X25519":
            ctx["priv"] = x25519.X25519PrivateKey.generate()
            ctx["peer"] = x25519.X25519PrivateKey.generate().public_key()
        else:  # ECDH-P256 / P384
            ctx["curve"] = ec.SECP256R1() if "256" in alg else ec.SECP384R1()
            ctx["priv"] = ec.generate_private_key(ctx["curve"])
            ctx["peer"] = ec.generate_private_key(ctx["curve"]).public_key()
        return ctx

    def run_keygen(self, c):
        from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519
        a = c["alg"]
        if a.startswith("RSA"):
            rsa.generate_private_key(65537, int(a.split("-")[1]))
        elif a == "X25519":
            x25519.X25519PrivateKey.generate()
        else:
            ec.generate_private_key(c["curve"])

    # "encapsulation" for ECDH = ephemeral keygen + shared-secret derivation (initiator side);
    # for RSA = OAEP encryption of a 32-byte secret. "decapsulation" = derive with the static key / OAEP decrypt.
    def run_encapsulation(self, c):
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        a = c["alg"]
        if a.startswith("RSA"):
            c["pub"].encrypt(b"k" * 32, c["oaep"])
        elif a == "X25519":
            e = x25519.X25519PrivateKey.generate()
            e.exchange(c["peer"])
        else:
            e = ec.generate_private_key(c["curve"])
            e.exchange(ec.ECDH(), c["peer"])

    def run_decapsulation(self, c):
        from cryptography.hazmat.primitives.asymmetric import ec
        a = c["alg"]
        if a.startswith("RSA"):
            c["priv"].decrypt(c["ct"], c["oaep"])
        elif a == "X25519":
            c["priv"].exchange(c["peer"])
        else:
            c["priv"].exchange(ec.ECDH(), c["peer"])

    def run_sign(self, c):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        if c["alg"].startswith("RSA"):
            c["priv"].sign(c["msg"], c["pss"], hashes.SHA256())
        else:
            c["priv"].sign(c["msg"], ec.ECDSA(c["hash"]))

    def run_verify(self, c):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        if c["alg"].startswith("RSA"):
            c["pub"].verify(c["sig"], c["msg"], c["pss"], hashes.SHA256())
        else:
            c["pub"].verify(c["sig"], c["msg"], ec.ECDSA(c["hash"]))


class PurePythonPQCAdapter(BaseAdapter):
    name = "pure-python-pqc"
    caveat = ("Pure-Python educational reference implementations (kyber-py / dilithium-py). Timings are real for this "
              "environment but far slower than optimized native code and not representative of production performance. "
              "Do not compare directly against native classical timings.")

    def __init__(self):
        import importlib.metadata as md
        v = []
        for pkg in ("kyber-py", "dilithium-py"):
            try:
                v.append(f"{pkg} {md.version(pkg)}")
            except Exception:
                pass
        self.library = "; ".join(v) + " (pure Python)"
        self.compiler = platform.python_compiler()

    def is_available(self):
        try:
            import dilithium_py.ml_dsa  # noqa: F401
            import kyber_py.ml_kem  # noqa: F401
            return True
        except Exception:
            return False

    def supports(self, alg):
        return alg in KEM_ALGS + DSA_ALGS

    def max_iterations(self, alg, op):
        return 50

    def setup(self, alg):
        from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
        impl = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024,
                "ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}[alg]
        ctx = {"impl": impl, "alg": alg}
        if alg.startswith("ML-KEM"):
            ctx["pk"], ctx["sk"] = impl.keygen()
            ctx["ss"], ctx["ct"] = impl.encaps(ctx["pk"])
        else:
            ctx["msg"] = b"qsamp benchmark message" * 2
            ctx["pk"], ctx["sk"] = impl.keygen()
            ctx["sig"] = impl.sign(ctx["sk"], ctx["msg"])
        return ctx

    def run_keygen(self, c): c["impl"].keygen()
    def run_encapsulation(self, c): c["impl"].encaps(c["pk"])
    def run_decapsulation(self, c): c["impl"].decaps(c["sk"], c["ct"])
    def run_sign(self, c): c["impl"].sign(c["sk"], c["msg"])
    def run_verify(self, c): c["impl"].verify(c["pk"], c["msg"], c["sig"])


class LiboqsAdapter(BaseAdapter):
    """Native liboqs (python-oqs). Used only if `oqs` is importable. Not exercised in
    this repository's CI; provided as the integration point for native measurements."""
    name = "liboqs"
    caveat = "Native liboqs build; results depend on how liboqs was compiled (CPU features, compiler flags)."

    def is_available(self):
        try:
            import oqs  # noqa: F401
            return True
        except Exception:
            return False

    def __init__(self):
        self.library = "liboqs (python-oqs)"
        self.compiler = "native (see liboqs build)"

    @staticmethod
    def mechanism(alg):
        """liboqs naming differs by release (e.g. SLH-DSA-SHA2-128s is
        SLH_DSA_PURE_SHA2_128S in 0.14+ and SPHINCS+-SHA2-128s-simple before);
        return the enabled name for `alg`, or None."""
        import oqs
        enabled = set(oqs.get_enabled_kem_mechanisms()) | set(oqs.get_enabled_sig_mechanisms())
        candidates = [alg]
        if alg.startswith("SLH-DSA-"):
            rest = alg[len("SLH-DSA-"):]
            candidates += [f"SLH_DSA_PURE_{rest.replace('-', '_').upper()}", f"SPHINCS+-{rest}-simple"]
        return next((c for c in candidates if c in enabled), None)

    def supports(self, alg):
        if not self.is_available():
            return False
        try:
            return self.mechanism(alg) is not None
        except Exception:
            return False

    def setup(self, alg):
        import oqs
        name = self.mechanism(alg)
        ctx = {"alg": alg}
        # Objects are created once here: constructing a liboqs object inside the
        # timed loop would measure allocation/initialisation, not the operation.
        if alg.startswith("ML-KEM"):
            k = oqs.KeyEncapsulation(name)
            ctx["pk"] = k.generate_keypair()
            ctx["kem"] = k
            ctx["ct"], _ = k.encap_secret(ctx["pk"])
            ctx["keygen_obj"] = oqs.KeyEncapsulation(name)  # separate so keygen does not replace kem's secret key
            ctx["encap_obj"] = oqs.KeyEncapsulation(name)
        else:
            s = oqs.Signature(name)
            ctx["pk"] = s.generate_keypair()
            ctx["sig_obj"] = s
            ctx["msg"] = b"qsamp benchmark message" * 2
            ctx["sig"] = s.sign(ctx["msg"])
            ctx["keygen_obj"] = oqs.Signature(name)
            ctx["verify_obj"] = oqs.Signature(name)
        return ctx

    def run_keygen(self, c): c["keygen_obj"].generate_keypair()
    def run_encapsulation(self, c): c["encap_obj"].encap_secret(c["pk"])
    def run_decapsulation(self, c): c["kem"].decap_secret(c["ct"])
    def run_sign(self, c): c["sig_obj"].sign(c["msg"])
    def run_verify(self, c): c["verify_obj"].verify(c["msg"], c["sig"], c["pk"])


class DemoAdapter(BaseAdapter):
    """Synthetic, deterministic numbers for algorithms with no available implementation.
    ALWAYS labelled data_source='demo'; must never be presented as measurements."""
    name = "demo"
    data_source = "demo"
    library = "QS-AMP demo generator (no cryptographic operation performed)"
    compiler = "n/a"
    caveat = "DEMO BENCHMARK: values are synthetic placeholders generated deterministically; no cryptographic operation was executed."

    def supports(self, alg):
        return alg in ALL_ALGS

    def measure(self, alg, op, iterations, ctx):
        base = 0.05 + (int(hashlib.sha256(f"{alg}:{op}".encode()).hexdigest()[:6], 16) % 4000) / 1000.0
        samples = []
        for i in range(iterations):
            h = int(hashlib.sha256(f"{alg}:{op}:{i}".encode()).hexdigest()[:6], 16) / 0xFFFFFF
            samples.append(base * (0.9 + 0.2 * h))
        mem = 8 + (int(hashlib.sha256(alg.encode()).hexdigest()[:4], 16) % 500) / 10.0
        return samples, mem


def get_adapters():
    adapters = []
    for cls in (LiboqsAdapter, CryptographyAdapter, PurePythonPQCAdapter):
        try:
            a = cls()
            if a.is_available():
                adapters.append(a)
        except Exception:
            continue
    if settings.DEMO_MODE:
        adapters.append(DemoAdapter())
    return adapters


def pick_adapter(alg, adapters, force_demo=False):
    if force_demo:
        return next((a for a in adapters if a.data_source == "demo"), None)
    for a in adapters:
        if a.data_source != "demo" and a.supports(alg):
            return a
    return next((a for a in adapters if a.data_source == "demo" and a.supports(alg)), None)


def environment_info():
    return {"platform": platform.platform(), "cpu": platform.processor() or platform.machine(),
            "os": f"{platform.system()} {platform.release()}", "python": platform.python_version(),
            "compiler": platform.python_compiler()}


def capabilities():
    env = environment_info()
    adapters = get_adapters()
    algs = []
    for alg in ALL_ALGS:
        a = pick_adapter(alg, adapters)
        algs.append({"algorithm": alg, "operations": supported_operations(alg),
                     "adapter": a.name if a else None, "data_source": a.data_source if a else None,
                     "library": a.library if a else None, "caveat": a.caveat if a else "No implementation available."})
    return {"environment": env, "algorithms": algs, "demo_mode": settings.DEMO_MODE,
            "adapters": [{"name": a.name, "data_source": a.data_source, "library": a.library} for a in adapters]}


STALE_RUN_AFTER = timedelta(minutes=30)


def _validate_request(algorithms, operations, iterations, force_demo):
    if not isinstance(algorithms, list) or not algorithms:
        raise ServiceError("validation_error", "Select at least one algorithm.")
    algorithms = list(dict.fromkeys(algorithms))  # de-duplicate, keep order
    bad = [a for a in algorithms if a not in ALL_ALGS]
    if bad:
        raise ServiceError("validation_error", f"Unsupported algorithm(s): {', '.join(map(str, bad))}")
    if operations is not None:
        if not isinstance(operations, list) or any(o not in OPERATIONS for o in operations):
            raise ServiceError("validation_error", f"Operations must be a list drawn from: {', '.join(OPERATIONS)}.")
    try:
        iterations = max(1, min(int(iterations or 20), 200))
    except (TypeError, ValueError):
        raise ServiceError("validation_error", "Iterations must be a whole number between 1 and 200.")
    if not isinstance(force_demo, bool):
        force_demo = str(force_demo).strip().lower() in ("1", "true", "yes", "on")
    if force_demo and not settings.DEMO_MODE:
        raise ServiceError("demo_disabled", "Demo benchmarks are disabled (DEMO_MODE is off).", 403)
    adapters = get_adapters()
    missing = [a for a in algorithms if pick_adapter(a, adapters, force_demo) is None]
    if missing:
        raise ServiceError("no_adapter", f"No benchmark implementation available for {', '.join(missing)}.")
    return algorithms, operations, iterations, force_demo


def recover_stale_runs(org=None):
    """Runs whose worker died stay 'running' forever; fail them."""
    runs = BenchmarkRun.objects.filter(status="running", updated_at__lt=timezone.now() - STALE_RUN_AFTER)
    if org is not None:
        runs = runs.filter(organization=org)
    return runs.update(status="failed", error="The benchmark was interrupted before it finished. Run it again.")


def run_benchmark(org, user, algorithms, operations=None, iterations=20, name="", force_demo=False, background=False):
    """Validate, persist and execute a benchmark. With background=True the run is
    returned immediately with status 'running' and measured off the request
    thread (Celery when enabled, otherwise a worker thread), so a slow pure-Python
    run can never hit the web server's request timeout."""
    algorithms, operations, iterations, force_demo = _validate_request(algorithms, operations, iterations, force_demo)
    if BenchmarkRun.objects.filter(organization=org, status="running",
                                   updated_at__gte=timezone.now() - STALE_RUN_AFTER).exists():
        raise ServiceError("benchmark_in_progress", "A benchmark is already running for this workspace.", 409)
    env = environment_info()
    run = BenchmarkRun.objects.create(
        organization=org, name=(name or f"Benchmark {', '.join(algorithms[:3])}")[:200], algorithms=algorithms,
        operations=operations or [], iterations=iterations, platform=env["platform"], cpu=env["cpu"],
        os=env["os"], compiler=env["compiler"], created_by=user, status="running")
    if not background or settings.SCAN_SYNC:
        execute_run(run.id, force_demo)
        run.refresh_from_db()
        if run.status == "failed":
            raise ServiceError("benchmark_failed", f"Benchmark failed: {run.error}", 500)
    elif settings.CELERY_ENABLED:
        from .tasks import execute_run_task
        transaction.on_commit(lambda: execute_run_task.delay(str(run.id), force_demo))
    else:
        transaction.on_commit(lambda: threading.Thread(target=execute_run, args=(run.id, force_demo), daemon=True).start())
    return run


def execute_run(run_id, force_demo=False):
    close_old_connections()
    run = BenchmarkRun.objects.get(pk=run_id)
    org, env = run.organization, environment_info()
    iterations, operations = run.iterations, run.operations or None
    adapters = get_adapters()
    rows, used = [], set()
    try:
        for alg in run.algorithms:
            adapter = pick_adapter(alg, adapters, force_demo)
            if adapter is None:
                raise ServiceError("no_adapter", f"No benchmark implementation available for {alg}.")
            used.add(adapter.name)
            ctx = adapter.setup(alg) if adapter.data_source != "demo" else {}
            ops = [o for o in (operations or supported_operations(alg)) if o in supported_operations(alg)]
            for op in ops:
                n = min(iterations, adapter.max_iterations(alg, op))
                samples, mem = adapter.measure(alg, op, n, ctx)
                mean = statistics.fmean(samples)
                notes = adapter.caveat
                if n < iterations:
                    notes += f" Iterations capped at {n} for this operation."
                rows.append(BenchmarkResult(
                    organization=org, run=run, algorithm=alg, version=adapter.library.split(" (")[0],
                    platform=env["platform"], cpu=env["cpu"], os=env["os"], library=adapter.library,
                    compiler=adapter.compiler, operation=op, iterations=n, median=statistics.median(samples),
                    mean=mean, min=min(samples), max=max(samples), memory_kb=mem,
                    throughput_ops=(1000.0 / mean) if mean else None, latency_ms=statistics.median(samples),
                    data_source=adapter.data_source, notes=notes))
            BenchmarkRun.objects.filter(pk=run.pk).update(updated_at=timezone.now())  # heartbeat
        BenchmarkResult.objects.bulk_create(rows)
        run.status, run.adapter = "completed", ", ".join(sorted(used))
    except Exception as e:
        run.status, run.error = "failed", getattr(e, "message", None) or str(e)
    finally:
        run.adapter = ", ".join(sorted(used))
        run.save()
        close_old_connections()
    return run
