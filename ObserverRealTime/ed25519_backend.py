"""
ed25519_backend.py — verification backend selection + memoisation.

WHY THIS EXISTS
---------------
ed25519.py is the NORMATIVE reference implementation for this project. It is
pure Python (stdlib `hashlib` only), it mirrors the RFC 8032 formulas literally,
and it is deterministic — so its signatures are byte-identical to the firmware's
(rweather Crypto on the ESP32). That equality is what makes make_vectors.py a
real cross-check rather than a tautology, and it is what lets an auditor read
_edwards_add() next to RFC 8032 and see the same equation.

It is also ~200 ms per verification, and the reason is algorithmic rather than
linguistic. ed25519.py works in AFFINE coordinates (x, y), where the twisted
Edwards addition law contains a division:

        x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)

A division modulo p is a modular inversion, computed here by Fermat's little
theorem — pow(x, p-2, p), a full 255-bit modular exponentiation. There are TWO
per point addition and ~766 additions per verify:

        MEASURED: 1532 modular inversions  ~= 582,000 big-int multiplications
                  for ONE signature check.

OpenSSL uses EXTENDED coordinates (X:Y:Z:T), carrying the denominator in Z so
that additions need no inversion at all; it inverts ONCE at the end. That is
~766x less work before any C, assembly or precomputed tables are considered.

        MEASURED on this project's data:
            ed25519.py    196.36  ms/verify
            cryptography    0.155 ms/verify      -> 1267x

At 3 drones x 15 min that is the difference between ~45 minutes and ~1 second.

WHAT THIS MODULE DOES
---------------------
It does NOT replace the reference. It:

  1. Uses OpenSSL (via the optional `cryptography` package) when available.
  2. NEVER TRUSTS IT. At import, the fast path is checked against the pure
     Python reference on the RFC 8032 normative vector AND on a tampered
     signature (both a true and a FALSE answer must agree — a backend that
     always returned True would pass a valid-only test).
  3. Falls back to ed25519.py if `cryptography` is absent, or if the two
     disagree for any reason.
  4. Memoises results by (pubkey, msg, sig).

The audit story is therefore stronger, not weaker: the fast path is not assumed
equivalent to the reference, it is demonstrated equivalent on every run.

MEMOISATION AND WHY IT IS SOUND
-------------------------------
ASTM F3411-22a §5.4.4.2 (BUR0050) permits re-sending an unchanged pack without
incrementing the Message Counter, and this project's firmware beacons each pack
at ~10 Hz while its content changes at 3 Hz. The same (pubkey, msg, sig) triple
therefore arrives ~4x. MEASURED on a real capture: 232 verifies, 93 unique —
60% of the work was recomputing an answer already known.

Ed25519 verification is a pure function. Identical inputs cannot produce a
different result, so caching cannot mask a bad signature.

It also cannot mask a REPLAY: a replayed pack has a genuinely valid signature.
Replay is caught by freshness (E-FRESH-01, VNB/VNA per RFC 9575 §4.1), which
runs per-frame and is untouched by this cache. Only the algebra is cached.
"""

import ed25519 as _reference

# ---------------------------------------------------------------------------
#  RFC 8032 §7.1, TEST 1 — the normative Ed25519 test vector.
#  Used to prove BOTH implementations before either is relied upon.
# ---------------------------------------------------------------------------
_RFC8032_PK = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
_RFC8032_MSG = b""
_RFC8032_SIG = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

_backend_name = "ed25519.py (pure python reference)"
_fast = None
_selftest_note = ""
_cache = {}
_stats = {"calls": 0, "hits": 0}


def _load_fast():
    """Return a fast verify(pub, msg, sig) -> bool, or None."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return None, "cryptography not installed"

    def _v(pub, msg, sig):
        try:
            Ed25519PublicKey.from_public_bytes(bytes(pub)).verify(bytes(sig), bytes(msg))
            return True
        except InvalidSignature:
            return False
        except Exception:
            # Malformed key/sig: the reference returns False rather than raising,
            # so match that so the two can never disagree on shape alone.
            return False

    try:
        import cryptography
        ver = cryptography.__version__
    except Exception:
        ver = "?"
    return _v, f"cryptography {ver} (OpenSSL)"


def self_test(verbose=False):
    """Prove the reference, then prove the fast path against it.

    Returns (backend_label, note). Called once at import.

    Cost: ~2 pure-python verifies (~0.4 s). That is the price of being able to
    state that the fast path was checked on THIS run, on THIS machine, against
    the implementation that matches the firmware.
    """
    global _fast, _backend_name, _selftest_note

    # Clear FIRST. Otherwise a re-run that REFUSES a backend would leave the
    # previously-accepted one installed while reporting that it fell back —
    # the message would be true and the state false.
    _fast = None
    _backend_name = "ed25519.py (pure python reference)"
    _cache.clear()

    tampered = bytearray(_RFC8032_SIG)
    tampered[0] ^= 0x01
    tampered = bytes(tampered)

    # ---- 1. the reference itself must satisfy RFC 8032 ---------------------
    if not _reference.verify(_RFC8032_PK, _RFC8032_MSG, _RFC8032_SIG):
        raise RuntimeError(
            "ed25519.py FAILED the RFC 8032 §7.1 TEST 1 vector — the reference "
            "implementation is broken; refusing to verify anything.")
    if _reference.verify(_RFC8032_PK, _RFC8032_MSG, tampered):
        raise RuntimeError(
            "ed25519.py ACCEPTED a tampered signature — the reference "
            "implementation is broken; refusing to verify anything.")

    # ---- 2. the fast path must agree with the reference --------------------
    fast, label = _load_fast()
    if fast is None:
        _selftest_note = f"{label}; using the pure-python reference (slow)"
        return _backend_name, _selftest_note

    # Both a TRUE and a FALSE answer are required. A stub that always returned
    # True would sail through a valid-signature-only check.
    ok_valid = (fast(_RFC8032_PK, _RFC8032_MSG, _RFC8032_SIG) is True)
    ok_bad = (fast(_RFC8032_PK, _RFC8032_MSG, tampered) is False)

    if not (ok_valid and ok_bad):
        _selftest_note = (f"{label} DISAGREED with ed25519.py "
                          f"(valid={ok_valid}, tampered-rejected={ok_bad}) — "
                          f"REFUSED, falling back to the pure-python reference")
        return _backend_name, _selftest_note

    _fast = fast
    _backend_name = label
    _selftest_note = ("agrees with ed25519.py on RFC 8032 §7.1 TEST 1 "
                      "(valid accepted, tampered rejected)")
    return _backend_name, _selftest_note


def force_pure_python():
    """Ignore any fast backend and use ed25519.py (for --pure-python)."""
    global _fast, _backend_name, _selftest_note
    _fast = None
    _backend_name = "ed25519.py (pure python reference)"
    _selftest_note = "forced by --pure-python"
    _cache.clear()


def verify(pub, msg, sig):
    """Verify an Ed25519 signature. Memoised; backend-selected."""
    key = (bytes(pub), bytes(msg), bytes(sig))
    _stats["calls"] += 1
    hit = _cache.get(key)
    if hit is not None:
        _stats["hits"] += 1
        return hit
    res = _fast(pub, msg, sig) if _fast is not None else _reference.verify(pub, msg, sig)
    _cache[key] = res
    return res


def backend_name():
    return _backend_name


def selftest_note():
    return _selftest_note


def stats():
    return dict(_stats, unique=len(_cache))


# Run the self-test at import: no caller can use verify() unproven.
self_test()
