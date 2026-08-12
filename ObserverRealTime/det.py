#!/usr/bin/env python3
# =============================================================================
#  DRIP - Proof of Concept
#  CHECKPOINT 1, sub-step 1b:  DET computation (host-side)
# =============================================================================
#
#  WHAT THIS MODULE DOES
#    Turns an Ed25519 public key into a DRIP Entity Tag (DET) and verifies the
#    DET <-> public-key binding. It is the shared identity module: the value is
#    hard-coded into the ESP32 transmitter, and the OBSERVER imports the
#    verify_det_binding() function to check that a broadcast DET really was
#    derived from the broadcast public key.
#
#  STANDARDS
#    DET layout ............. RFC 9374 sec 3.1, Figure 1
#                             Prefix(28) | RAA(14) | HDA(14) | Suite(8) | hash(64)
#    ORCHID hash ............ RFC 9374 sec 3.5.2
#                             hash = cSHAKE128(Prefix|HID|Suite|HOST_ID, L=64,
#                                              N="", S=Context ID)
#    HOST_ID (EdDSA25519) ... the RAW 32-byte public key. NOT the 4-byte-wrapped
#                             HIP HOST_ID parameter (Curve|NULL|Key). Matches the
#                             RFC 9374 reference generator (Moskowitz det-gen.py)
#                             and deployed DRIP DNS; verified against a live DET.
#    cSHAKE128 .............. NIST SP 800-185 (built on Keccak / FIPS 202)
#    Ed25519 key ............ RFC 8032
#    Base32 alphabet ........ RFC 9374 Appendix C, Table 14
#
#  FIXED IDENTITY VALUES (this PoC)
#    Prefix    : 2001:30::/28            (RFC 9374 sec 3.1, Table 1 - spec-fixed)
#    Suite ID  : 5 = EdDSA/cSHAKE128     (RFC 9374 sec 3.2, Table 2 - spec-fixed)
#    Context ID: 0x00B5A69C795DF5D5F0087F56843F2C40  (RFC 9374 - spec-fixed)
#    RAA / HDA : 1000 / 2000             (arbitrary TEST values, no real registry)
#
#  VALIDATION (run `python3 det.py`)
#    1. Keccak core .... our SHAKE128 == hashlib.shake_128 over random inputs
#    2. cSHAKE path .... reproduces the official NIST SP 800-185 "Email
#                        Signature" cSHAKE128 sample (non-empty customization)
#    3. HID packing .... reproduces RFC 9374 App. B.1 (RAA10/HDA20 -> 2001:0030:0280:1405)
#    4. Round-trip ..... compute_det(UA_PUB) == the recorded DET, and the
#                        binding verifier accepts the correct key, rejects others
#
#  NOTE: depends only on the Python standard library.
# =============================================================================

import hashlib
import ipaddress

# =============================================================================
#  Keccak-f[1600] permutation (FIPS 202)
# =============================================================================
_RHO = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
       0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_MASK = (1 << 64) - 1


def _rol(x, n):
    """Rotate a 64-bit lane left by n bits."""
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(state):
    """Apply the 24-round Keccak-f[1600] permutation to a 200-byte state."""
    A = [int.from_bytes(state[8 * i:8 * i + 8], 'little') for i in range(25)]
    for rnd in range(24):
        # theta
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            A[i] ^= D[i % 5]
        # rho + pi
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(A[x + 5 * y], _RHO[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                A[x + 5 * y] = (B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y])) & _MASK
        # iota
        A[0] ^= _RC[rnd]
    out = bytearray(200)
    for i in range(25):
        out[8 * i:8 * i + 8] = A[i].to_bytes(8, 'little')
    return out


def _keccak(rate, msg, suffix, outlen):
    """Sponge: absorb `msg` at the given rate (bytes) with domain `suffix`,
    then squeeze `outlen` bytes. pad10*1 padding (FIPS 202)."""
    state = bytearray(200)
    m = bytearray(msg)
    m.append(suffix)                       # domain-separation bits + first pad bit
    while len(m) % rate:
        m.append(0)
    m[-1] |= 0x80                          # final pad bit
    for off in range(0, len(m), rate):
        for i in range(rate):
            state[i] ^= m[off + i]
        state = _keccak_f(state)
    out = bytearray()
    while len(out) < outlen:
        out += state[:rate]
        if len(out) < outlen:
            state = _keccak_f(state)
    return bytes(out[:outlen])


# SHAKE128: rate 168 bytes (capacity 256 bits), SHAKE domain suffix 0x1F (FIPS 202)
def shake128(x, outlen):
    return _keccak(168, x, 0x1F, outlen)


# =============================================================================
#  cSHAKE128 (NIST SP 800-185)
# =============================================================================
def _left_encode(x):
    """left_encode(x) per NIST SP 800-185 sec 2.3.1."""
    if x == 0:
        return b'\x01\x00'
    k = (x.bit_length() + 7) // 8
    return bytes([k]) + x.to_bytes(k, 'big')


def _encode_string(s):
    """encode_string(S) = left_encode(len(S) in BITS) || S."""
    return _left_encode(len(s) * 8) + s


def _bytepad(x, w):
    """bytepad(X, w) = left_encode(w) || X || 0* (to a multiple of w bytes)."""
    z = _left_encode(w) + x
    if len(z) % w:
        z += b'\x00' * (w - len(z) % w)
    return z


def cshake128(x, outlen, N=b'', S=b''):
    """cSHAKE128(X, L, N, S) per NIST SP 800-185 sec 3.3.
       - When N and S are both empty it degenerates to SHAKE128.
       - Otherwise: KECCAK[256](bytepad(encode_string(N)||encode_string(S),168)||X||00, L),
         i.e. the cSHAKE domain suffix is 0x04 instead of SHAKE's 0x1F."""
    if N == b'' and S == b'':
        return shake128(x, outlen)
    prefix = _bytepad(_encode_string(N) + _encode_string(S), 168)
    return _keccak(168, prefix + x, 0x04, outlen)


# =============================================================================
#  DET construction (RFC 9374)
# =============================================================================
DET_PREFIX = ipaddress.IPv6Network("2001:30::/28")            # RFC 9374 sec 3.1, Table 1
CONTEXT_ID = bytes.fromhex("00B5A69C795DF5D5F0087F56843F2C40")  # RFC 9374
SUITE_EDDSA_CSHAKE128 = 5                                     # RFC 9374 sec 3.2, Table 2
EDDSA25519_CURVE = 1                                         # RFC 9374 sec 3.4, Table 5


def host_id_eddsa25519(pub32):
    """EdDSA25519 HIP HOST_ID PARAMETER - RFC 9374 sec 3.4.1.1, Figure 2:
       EdDSA Curve (2 bytes) || NULL (2 bytes) || Public Key (32 bytes).

    NOTE: this is the HIP protocol parameter framing. It is NOT used for the DET
    ORCHID hash (see compute_det). Kept for reference / possible HIP-RR use."""
    assert len(pub32) == 32
    return EDDSA25519_CURVE.to_bytes(2, 'big') + b'\x00\x00' + pub32


def _upper64(raa, hda, suite):
    """Upper 64 bits of the DET - RFC 9374 Fig 1 / App B.1:
       Prefix(28) | RAA(14) | HDA(14) | Suite(8), bit-packed into 8 bytes."""
    assert 0 <= raa <= 0x3FFF and 0 <= hda <= 0x3FFF
    prefix28 = int(DET_PREFIX.network_address) >> 100        # top 28 bits of the /28
    v = (prefix28 & ((1 << 28) - 1)) << 36
    v |= (raa & 0x3FFF) << 22
    v |= (hda & 0x3FFF) << 8
    v |= (suite & 0xFF)
    return v.to_bytes(8, 'big')


def compute_det(pub32, raa, hda, suite=SUITE_EDDSA_CSHAKE128):
    """Compute the 16-byte DET from an Ed25519 public key - RFC 9374 sec 3.5.2.

       DET = upper64 || cSHAKE128(upper64 || HOST_ID, L=64, N="", S=Context ID)

       *** HOST_ID here is the RAW 32-byte public key, NOT the 4-byte-wrapped HIP
       HOST_ID parameter. *** RFC 9374 §3.5.2 ends the hash input with HOST_ID;
       the HIP HOST_ID PARAMETER framing (Curve|NULL|Key, §3.4.1.1/Fig 2) is for
       HIP exchanges and is NOT hashed here. The raw-key form is what the
       reference generator (Moskowitz det-gen.py) and deployed DRIP DNS produce;
       verified byte-for-byte against a live DET
       (2001:30:3ff8:405:d952:5618:fbc9:c3cf). An earlier version wrapped the key
       with 0x0001|0x0000 and produced DETs that matched no other implementation.
    """
    upper = _upper64(raa, hda, suite)
    orchid_input = upper + bytes(pub32)                      # RAW 32-byte HI, no wrapper
    hash64 = cshake128(orchid_input, 8, N=b'', S=CONTEXT_ID)  # L = 64 bits = 8 bytes
    return upper + hash64


def parse_det(det16):
    """Extract (prefix28, raa, hda, suite, hash64) from a 16-byte DET."""
    assert len(det16) == 16
    upper = int.from_bytes(det16[:8], 'big')
    return {
        "prefix28": upper >> 36,
        "raa": (upper >> 22) & 0x3FFF,
        "hda": (upper >> 8) & 0x3FFF,
        "suite": upper & 0xFF,
        "hash64": det16[8:],
    }


def verify_det_binding(det16, pub32):
    """Core DRIP check (used by the observer): does this DET really derive from
       this public key? Re-derives the DET from pub32 using the hierarchy fields
       carried inside the DET itself, and compares. Also rejects a wrong prefix."""
    f = parse_det(det16)
    if f["prefix28"] != (int(DET_PREFIX.network_address) >> 100):
        return False
    return compute_det(pub32, f["raa"], f["hda"], f["suite"]) == det16


# =============================================================================
#  Base32 rendering (RFC 9374 Appendix C, Table 14)
# =============================================================================
_BASE32_ALPHABET = "0123456789ABCDEFGHJKLMNPQRTUVWXY"  # omits I, O, S, Z


def base32_appendix_c(data):
    """Compact Base32 rendering of raw bytes using the RFC 9374 App. C alphabet.
       NOTE: this is a plain 5-bit Base32 of the 16-byte DET, NOT the full
       CTA 2063-A serial-number encoding (RFC 9374 sec 4.2), which is a separate,
       more involved mapping we can add later if needed."""
    bits = ''.join(f'{b:08b}' for b in data)
    while len(bits) % 5:
        bits += '0'
    return ''.join(_BASE32_ALPHABET[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


# =============================================================================
#  This PoC's hard-coded identity (from sub-step 1a, on-device keygen)
# =============================================================================
TEST_RAA = 1000
TEST_HDA = 2000

UA_PUB = bytes([
    0x8B, 0x65, 0xB2, 0x65, 0xA4, 0x96, 0xE3, 0x20, 0x46, 0xCF, 0xA3, 0x78, 0xB5, 0xA5, 0xFB, 0x2E,
    0x87, 0x7A, 0x97, 0x72, 0x3E, 0x55, 0x7C, 0xB5, 0xF0, 0xD2, 0x18, 0x48, 0xBF, 0xE9, 0x44, 0x77,
])

# DET derived from UA_PUB with (RAA=1000, HDA=2000, suite=5), RAW-KEY method.
# Recorded so the self-test can confirm the derivation is reproducible.
UA_DET = bytes.fromhex("20010030fa07d0054dfdc31103e51953")


# =============================================================================
#  Self-tests
# =============================================================================
def _self_test():
    import os
    import random

    # [1] Keccak core: our SHAKE128 must equal the reference hashlib.shake_128.
    for _ in range(200):
        x = os.urandom(random.randint(0, 500))
        assert shake128(x, 32) == hashlib.shake_128(x).digest(32)

    # [2] cSHAKE customization path: official NIST SP 800-185 cSHAKE128 sample
    #     (N="", S="Email Signature", X=0x00010203, L=256).
    kat = cshake128(bytes([0, 1, 2, 3]), 32, N=b'', S=b'Email Signature')
    assert kat.hex() == "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5", kat.hex()

    # [3] HID packing: RFC 9374 App. B.1 worked example.
    assert _upper64(10, 20, 5).hex() == "2001003002801405", _upper64(10, 20, 5).hex()

    # [4] Round-trip + binding verifier on our own identity.
    d = compute_det(UA_PUB, TEST_RAA, TEST_HDA)
    assert d == UA_DET, d.hex()
    assert verify_det_binding(UA_DET, UA_PUB) is True
    wrong = bytearray(UA_PUB); wrong[0] ^= 0x01           # flip one bit of the key
    assert verify_det_binding(UA_DET, bytes(wrong)) is False
    print("self-test OK (Keccak, NIST cSHAKE128 KAT, HID packing, DET round-trip + binding)")


if __name__ == "__main__":
    _self_test()
    det = compute_det(UA_PUB, TEST_RAA, TEST_HDA)
    f = parse_det(det)
    print()
    print("==== DRIP Entity Tag (DET) ====")
    print(f"  RAA / HDA / Suite : {f['raa']} / {f['hda']} / {f['suite']}")
    print(f"  DET (hex)         : {det.hex()}")
    print(f"  DET (IPv6)        : {ipaddress.IPv6Address(det)}")
    print(f"  upper 64 (id)     : {det[:8].hex()}")
    print(f"  lower 64 (hash)   : {det[8:].hex()}")
    print(f"  Base32 (App. C)   : {base32_appendix_c(det)}")
    print()
    print("  C array for firmware / observer:")
    print("  const uint8_t UA_DET[16] = { " +
          ", ".join(f"0x{b:02X}" for b in det) + " };")
