import os, det, ed25519

# --- choose the hierarchy numbers for this identity ---
RAA = 255
HDA = 14340

# --- generate the keypair ---
seed = os.urandom(32)               # the PRIVATE key (32 random bytes)
pub  = ed25519.derive_pubkey(seed)  # the PUBLIC key (HI), derived from the seed
det_bytes = det.compute_det(pub, RAA, HDA)   # the DET (raw-key method)

# --- print everything you need ---
print("SEED  (private):", seed.hex().upper())
print("PUB   (public) :", pub.hex().upper())
print("DET (hex)      :", det_bytes.hex().upper())
import ipaddress
print("DET (IPv6)     :", ipaddress.IPv6Address(det_bytes))

# --- self-check: prove the DET really derives from this key ---
print("binding OK     :", det.verify_det_binding(det_bytes, pub))