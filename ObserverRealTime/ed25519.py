#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - ed25519.py
#  Pure-Python, stdlib-only Ed25519 (RFC 8032) — sign, verify, derive pubkey.
#
#  Why from scratch: keeps the observer dependency-free, exactly like det.py's
#  from-scratch cSHAKE128. Ed25519 signing is DETERMINISTIC (RFC 8032), so the
#  signatures this module produces are byte-identical to those produced on the
#  ESP32 by the rweather/arduinolibs Crypto library for the same key + message.
#
#  Verified in __main__ against the RFC 8032 Section 7.1 test vectors.
#
#  Reference: RFC 8032 "Edwards-Curve Digital Signature Algorithm (EdDSA)".
# =============================================================================

import hashlib

# ---- Curve constants (RFC 8032 §5.1) --------------------------------------
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493   # group order
_d = (-121665 * pow(121666, _p - 2, _p)) % _p             # -121665/121666
_I = pow(2, (_p - 1) // 4, _p)                            # sqrt(-1)
_B_y = (4 * pow(5, _p - 2, _p)) % _p
_B_x = None  # computed at import


def _sha512(b):
    return hashlib.sha512(b).digest()


def _inv(x):
    return pow(x, _p - 2, _p)


def _x_recover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != 0:
        x = _p - x
    return x


_B_x = _x_recover(_B_y)
_B = (_B_x % _p, _B_y % _p)


def _edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    denom = _d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + denom)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - denom)
    return (x3 % _p, y3 % _p)


def _scalarmult(P, e):
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encode_point(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def _decode_int(s):
    return int.from_bytes(s, 'little')


def _decode_point(s):
    y = sum(2 ** i * _bit(s, i) for i in range(255))
    x = _x_recover(y)
    if x & 1 != _bit(s, 255):
        x = _p - x
    P = (x, y)
    if not _is_on_curve(P):
        raise ValueError("decompressed point not on curve")
    return P


def _is_on_curve(P):
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _p == 0


def _secret_expand(seed):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = _sha512(seed)
    a = _decode_int(h[:32])
    a &= (1 << 254) - 8          # clear low 3 bits, clear bit 255, set bit 254
    a |= (1 << 254)
    return a, h[32:]


def derive_pubkey(seed):
    """32-byte seed -> 32-byte Ed25519 public key."""
    a, _ = _secret_expand(seed)
    return _encode_point(_scalarmult(_B, a))


def sign(seed, msg):
    """Deterministic Ed25519 signature (RFC 8032). seed=32B priv, returns 64B."""
    a, prefix = _secret_expand(seed)
    A = _encode_point(_scalarmult(_B, a))
    r = _decode_int(_sha512(prefix + msg)) % _L
    R = _encode_point(_scalarmult(_B, r))
    k = _decode_int(_sha512(R + A + msg)) % _L
    s = (r + k * a) % _L
    return R + s.to_bytes(32, 'little')


def verify(pubkey, msg, sig):
    """Return True iff sig (64B) is a valid Ed25519 signature of msg by pubkey (32B)."""
    if len(sig) != 64 or len(pubkey) != 32:
        return False
    try:
        R = _decode_point(sig[:32])
        A = _decode_point(pubkey)
    except Exception:
        return False
    s = _decode_int(sig[32:])
    if s >= _L:
        return False
    k = _decode_int(_sha512(sig[:32] + pubkey + msg)) % _L
    left = _scalarmult(_B, s)
    right = _edwards_add(R, _scalarmult(A, k))
    return left == right


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # RFC 8032 Section 7.1 test vectors (subset)
    vecs = [
        # (seed, pubkey, msg, sig)
        ("9d61b19deffkeyplaceholder", None, None, None),
    ]
    # Vector 1 (empty message) — RFC 8032 §7.1
    seed1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4"
                          "4449c5697b326919703bac031cae7f60")
    pub1  = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a"
                          "0ee172f3daa62325af021a68f707511a")
    sig1  = bytes.fromhex("e5564300c360ac729086e2cc806e828a"
                          "84877f1eb8e5d974d873e06522490155"
                          "5fb8821590a33bacc61e39701cf9b46b"
                          "d25bf5f0595bbe24655141438e7a100b")
    ok = True
    d = derive_pubkey(seed1)
    print("derive_pubkey vec1:", "PASS" if d == pub1 else "FAIL")
    ok &= (d == pub1)
    s = sign(seed1, b"")
    print("sign vec1         :", "PASS" if s == sig1 else "FAIL")
    ok &= (s == sig1)
    print("verify vec1       :", "PASS" if verify(pub1, b"", sig1) else "FAIL")
    ok &= verify(pub1, b"", sig1)
    print("reject tampered   :", "PASS" if not verify(pub1, b"x", sig1) else "FAIL")
    ok &= (not verify(pub1, b"x", sig1))

    # Vector 2 (1-byte message 0x72) — RFC 8032 §7.1
    seed2 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f"
                          "5b8a319f35aba624da8cf6ed4fb8a6fb")
    pub2  = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc"
                          "9c982ccf2ec4968cc0cd55f12af4660c")
    sig2  = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540"
                          "a2b27b5416503f8fb3762223ebdb69da"
                          "085ac1e43e15996e458f3613d0f11d8c"
                          "387b2eaeb4302aeeb00d291612bb0c00")
    print("sign vec2         :", "PASS" if sign(seed2, bytes([0x72])) == sig2 else "FAIL")
    ok &= (sign(seed2, bytes([0x72])) == sig2)
    print("verify vec2       :", "PASS" if verify(pub2, bytes([0x72]), sig2) else "FAIL")
    ok &= verify(pub2, bytes([0x72]), sig2)

    print("\nRFC 8032 self-test:", "ALL PASS" if ok else "FAILURES PRESENT")
