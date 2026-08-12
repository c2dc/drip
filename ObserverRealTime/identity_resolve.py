#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - identity_resolve.py
#  CHECKPOINT (observer): resolve a DRIP Entity Tag (DET) against a local
#  trusted-identities file.  *** STEP 1 — OFFLINE. NO NETWORK, NO DNSSEC. ***
#
#  WHAT THIS DOES (and, just as importantly, what it does NOT)
#  ----------------------------------------------------------------------------
#  Given a 16-byte DET and a trust structure loaded from hierarchy.json, this
#  module reports a LAYERED verdict. There are three genuinely different
#  questions hiding inside "is this DET valid", and they need different data:
#
#    (a) STRUCTURAL   - the DET is well-formed and its zones nest.
#                       Needs the DET ALONE. Pure arithmetic.
#                       RFC 9374 sec 3.3 (field layout) + RFC 9886 sec 6 (zones).
#
#    (b) ALLOW-LIST   - the DET, or the HDA/RAA it claims, appears in the local
#                       trusted-identities file. Needs the DET + the file.
#                       Reported at TWO levels (per the agreed design):
#                         HDA_TRUSTED    - the DET nests under a trusted HDA (the
#                                          way DNS delegation actually works: you
#                                          trust the HDA, you accept its children)
#                         UA_ENROLLED    - the exact UA DET is individually listed
#                                          in the file's "ua" array (stricter)
#
#    (c) CRYPTOGRAPHIC- the DET truly derives from a public key (the DET<->HI
#                       binding, RFC 9374 sec 3.5.2). Only possible when a key
#                       for THIS DET is on file. If no key is on file, this
#                       check is SKIPPED (E-KEY-01), never faked.
#
#  THE WALL (why (c) can be skipped but never forced):
#      A DET's low 64 bits are cSHAKE128(...). That is one-way. From a DET alone
#      you can read the RAA/HDA/Suite carried in the CLEAR, but you cannot
#      recover the public key, and you certainly cannot recover the private key.
#      So a trust file with no key can confirm "this DET claims RAA=x/HDA=y, is
#      on my allow-list, and its zones nest" - it CANNOT confirm "this key signed
#      it". This module states exactly which of (a)/(b)/(c) held and NEVER prints
#      a bare "VALID".
#
#  This module has NO I/O side effects: resolve_det() takes the trust data as an
#  argument and returns a Resolution. Step 2 (a DNSSEC resolver that WRITES into
#  hierarchy.json) will simply be another producer of that same trust structure,
#  so nothing here has to change when it arrives.
#
#  STANDARDS
#    DET field layout ........ RFC 9374 sec 3.3, Figure 1
#                              Prefix(28) | RAA(14) | HDA(14) | Suite(8) | hash(64)
#    DET<->key binding ....... RFC 9374 sec 3.5.2 (via det.verify_det_binding)
#    Zone delegation cuts .... RFC 9886 sec 6  (RAA -> /44, HDA -> /56)
#    Reverse-DNS FQDN ........ RFC 9886 sec 6  (built here for reporting; the
#                              live DNSSEC lookup that would USE it is Step 2)
# =============================================================================

import ipaddress

# det.py is the shared identity module: field decode + the cSHAKE128 binding.
# It is optional elsewhere in the observer, so we mirror that and degrade
# gracefully (structure + allow-list still work; only the binding check (c)
# needs it).
try:
    import det
    HAVE_DET = True
except Exception:
    HAVE_DET = False

# The DET prefix is spec-fixed (RFC 9374 sec 3.1, Table 1). We keep our own copy
# so this module is usable even if det.py is missing.
DET_PREFIX = ipaddress.IPv6Network("2001:30::/28")
_PREFIX28 = int(DET_PREFIX.network_address) >> 100

# Zone widths — RFC 9886 sec 6.
RAA_ZONE_BITS = 44
HDA_ZONE_BITS = 56


# ---------------------------------------------------------------------------
#  Zone helper — lifted verbatim (same math) from check_hierarchy.py::zone_of
#  so the observer and the hierarchy checker cut zones identically. RFC 9886 §6.
# ---------------------------------------------------------------------------
def zone_of(det_bytes, bits):
    """The DNS zone a DET belongs to: its prefix truncated to `bits`.

    The zone is fixed ENTIRELY by the RAA/HDA nibbles inside the DET; the key
    only affects the trailing 64-bit ORCHID hash, so it cannot influence
    delegation (RFC 9886 sec 6). This is why nesting is checkable from the DET
    alone, with no key.
    """
    nbytes = (bits + 7) // 8
    base = bytes(det_bytes[:nbytes]) + b"\x00" * (16 - nbytes)
    return ipaddress.IPv6Network((ipaddress.IPv6Address(base), bits), strict=False)


def det_to_ptr_fqdn(det_bytes):
    """DET -> reverse-DNS name under ip6.arpa. (RFC 9886 sec 6 / RFC 3596 §2.5).

    This is the name a Step-2 DNSSEC lookup WOULD query. We build it now purely
    for the report, so the operator can see the exact zone the DET maps to. No
    query is made here.
    """
    addr = ipaddress.IPv6Address(bytes(det_bytes))
    nibbles = f"{int(addr):032x}"
    return ".".join(reversed(nibbles)) + ".ip6.arpa."


# ===========================================================================
#  Trust file: the extended hierarchy.json.
#
#  BACKWARD-COMPATIBLE: the apex/raa/hda objects are unchanged. This step adds
#  an OPTIONAL top-level "ua" array of leaf drone identities:
#      "ua": [ { "det": "<32 hex>", "raa": 1000, "hda": 2000,
#                "public_key": "<64 hex>"   # OPTIONAL - drives check (c)
#              }, ... ]
#  A file with no "ua" key behaves exactly as before (only HDA-level trust is
#  possible for leaves).
# ===========================================================================

class TrustStore:
    """The trusted identities, indexed for DET resolution.

    Holds the apex/raa/hda anchor entities and the optional leaf "ua" entries.
    Everything is PUBLIC data (DETs, RAA/HDA numbers, public keys). Never a seed.
    """

    def __init__(self):
        self.apex = None            # dict or None
        self.raas = []              # list of dicts (raa, hda=0, det, public_key?)
        self.hdas = []              # list of dicts (raa, hda, det, public_key?)
        self.uas = []               # list of dicts (raa, hda, det, public_key?)
        # Fast lookup: DET bytes -> the entry that lists it (any level).
        self._by_det = {}

    def _index(self, entry, level):
        d = entry.get("_det_bytes")
        if d is not None:
            self._by_det[d] = (entry, level)

    def entry_for_det(self, det_bytes):
        """The trust entry that lists this EXACT DET, or (None, None)."""
        return self._by_det.get(bytes(det_bytes), (None, None))

    def key_for_det(self, det_bytes):
        """The registered public key (32 B) for this exact DET, or None.

        RFC 9374 sec 3.5.2 binds a DET to exactly ONE key, so this returns a
        single key, never a list.
        """
        entry, _ = self.entry_for_det(det_bytes)
        if entry is None:
            return None
        return entry.get("_pub_bytes")

    def trusted_hda_for(self, det_bytes):
        """The trusted HDA entry whose /56 zone contains det_bytes, or None.

        This is delegation-style trust: if the DET falls inside a trusted HDA's
        zone AND carries that HDA's RAA/HDA numbers, the HDA vouches for the
        namespace the DET lives in (RFC 9886 sec 6).
        """
        f = _fields(det_bytes)
        for hda in self.hdas:
            if hda["raa"] != f["raa"] or hda["hda"] != f["hda"]:
                continue
            zone = zone_of(hda["_det_bytes"], HDA_ZONE_BITS)
            if ipaddress.IPv6Address(bytes(det_bytes)) in zone:
                return hda
        return None

    def trusted_raa_for(self, det_bytes):
        """The trusted RAA entry whose /44 zone contains det_bytes, or None."""
        f = _fields(det_bytes)
        for raa in self.raas:
            if raa["raa"] != f["raa"]:
                continue
            zone = zone_of(raa["_det_bytes"], RAA_ZONE_BITS)
            if ipaddress.IPv6Address(bytes(det_bytes)) in zone:
                return raa
        return None


def _decode_entry(obj):
    """Validate + pre-decode one trust-file entity. Raises ValueError on junk."""
    d_hex = obj["det"]
    d = bytes.fromhex(d_hex)
    if len(d) != 16:
        raise ValueError(f"det '{d_hex}' is not 16 bytes")
    obj = dict(obj)
    obj["_det_bytes"] = d
    if "public_key" in obj and obj["public_key"]:
        p = bytes.fromhex(obj["public_key"])
        if len(p) != 32:
            raise ValueError(f"public_key for {d_hex} is not 32 bytes")
        obj["_pub_bytes"] = p
    # raa/hda default from the DET itself if not spelled out (they are carried
    # in the DET in the clear, RFC 9374 sec 3.3).
    f = _fields(d)
    obj.setdefault("raa", f["raa"])
    obj.setdefault("hda", f["hda"])
    return obj


def load_trust(path="hierarchy.json"):
    """Load the extended hierarchy.json into a TrustStore.

    Raises FileNotFoundError if absent (the caller decides what that means) and
    ValueError on a malformed entry - never silently trusts junk.
    """
    import json
    h = json.load(open(path, encoding="utf-8"))
    ts = TrustStore()

    if "apex" in h:
        ts.apex = _decode_entry(h["apex"]);  ts._index(ts.apex, "APEX")
    # Singular forms (one chain) - kept for backward compatibility.
    if "raa" in h:
        e = _decode_entry(h["raa"]);  ts.raas.append(e);  ts._index(e, "RAA")
    if "hda" in h:
        e = _decode_entry(h["hda"]);  ts.hdas.append(e);  ts._index(e, "HDA")
    # Plural forms (multiple chains) - the both-chains schema. A file may use
    # singular, plural, or both; all entries land in the same lists so the
    # resolver checks a DET against EVERY trusted RAA/HDA (RFC 9886 - an observer
    # trusts many authorities under the Apex).
    for i, raa in enumerate(h.get("raas", [])):
        try:
            e = _decode_entry(raa)
        except (KeyError, ValueError) as ex:
            raise ValueError(f"{path}: raas[{i}]: {ex}")
        ts.raas.append(e);  ts._index(e, "RAA")
    for i, hda in enumerate(h.get("hdas", [])):
        try:
            e = _decode_entry(hda)
        except (KeyError, ValueError) as ex:
            raise ValueError(f"{path}: hdas[{i}]: {ex}")
        ts.hdas.append(e);  ts._index(e, "HDA")
    # Optional leaf array (this step's schema addition). Absent -> [].
    for i, ua in enumerate(h.get("ua", [])):
        try:
            e = _decode_entry(ua)
        except (KeyError, ValueError) as ex:
            raise ValueError(f"{path}: ua[{i}]: {ex}")
        ts.uas.append(e);  ts._index(e, "UA")
    return ts


# ---------------------------------------------------------------------------
#  DET field decode. Uses det.parse_det when available (single source of truth,
#  RFC 9374 sec 3.3); falls back to an identical local decode otherwise.
# ---------------------------------------------------------------------------
def _fields(det_bytes):
    if HAVE_DET:
        return det.parse_det(bytes(det_bytes))
    upper = int.from_bytes(bytes(det_bytes)[:8], "big")
    return {
        "prefix28": upper >> 36,
        "raa": (upper >> 22) & 0x3FFF,
        "hda": (upper >> 8) & 0x3FFF,
        "suite": upper & 0xFF,
        "hash64": bytes(det_bytes)[8:],
    }


# ===========================================================================
#  The result object.
# ===========================================================================
class Resolution:
    """The layered verdict for one DET. Nothing is a bare boolean 'valid'.

    Fields:
      det           : 16 raw bytes
      fields        : {prefix28, raa, hda, suite, hash64}   (RFC 9374 sec 3.3)
      fqdn          : reverse ip6.arpa. name                (RFC 9886 sec 6)
      raa_zone/hda_zone : the /44 and /56 this DET declares  (RFC 9886 sec 6)
      prefix_ok     : prefix is 2001:30::/28                (else E-DET-01)
      raa_trusted   : the trusted RAA entry, or None
      hda_trusted   : the trusted HDA entry, or None        (HDA_TRUSTED level)
      ua_enrolled   : the exact-DET entry,   or None        (UA_ENROLLED level)
      registered_key: the one public key on file for this DET, or None
      binding       : one of 'VERIFIED' / 'MISMATCH' / 'NOT_CHECKED'
      findings      : list of (error_id, detail) annotations - see errors.py
    """

    __slots__ = ("det", "fields", "fqdn", "raa_zone", "hda_zone", "prefix_ok",
                 "raa_trusted", "hda_trusted", "ua_enrolled", "registered_key",
                 "binding", "findings")

    def __init__(self, det_bytes):
        self.det = bytes(det_bytes)
        self.fields = _fields(det_bytes)
        self.fqdn = det_to_ptr_fqdn(det_bytes)
        self.raa_zone = zone_of(det_bytes, RAA_ZONE_BITS)
        self.hda_zone = zone_of(det_bytes, HDA_ZONE_BITS)
        self.prefix_ok = (self.fields["prefix28"] == _PREFIX28)
        self.raa_trusted = None
        self.hda_trusted = None
        self.ua_enrolled = None
        self.registered_key = None
        self.binding = "NOT_CHECKED"
        self.findings = []

    # --- convenience predicates for the printer / callers --------------------
    @property
    def nests(self):
        """True if this DET falls under BOTH a trusted RAA /44 and HDA /56."""
        return self.raa_trusted is not None and self.hda_trusted is not None

    @property
    def on_allow_list(self):
        """True at either trust level: HDA delegation OR explicit UA enrolment."""
        return self.hda_trusted is not None or self.ua_enrolled is not None

    def det_hex(self):
        return self.det.hex().upper()

    def det_v6(self):
        return str(ipaddress.IPv6Address(self.det))


# ===========================================================================
#  The entry point.
# ===========================================================================
def resolve_det(det_bytes, trust):
    """Resolve one DET against a TrustStore. Returns a Resolution.

    Check order is fail-annotated, never fail-truncated: everything decodable is
    always populated; the error IDs annotate what did NOT hold. This mirrors the
    rest of the observer, which reports every finding rather than stopping at the
    first.
    """
    det_bytes = bytes(det_bytes)
    if len(det_bytes) != 16:
        raise ValueError("DET must be exactly 16 bytes")

    r = Resolution(det_bytes)

    # (a) STRUCTURAL — prefix. RFC 9374 sec 3.1 / Table 1.
    if not r.prefix_ok:
        r.findings.append(("E-DET-01",
                           f"prefix is {r.fields['prefix28']:07x}, "
                           f"expected {_PREFIX28:07x} (2001:30::/28)"))
        # A wrong prefix means this is not a DET at all; nesting/allow-list are
        # meaningless, so we stop the trust checks but STILL return the decode.
        return r

    # (b) ALLOW-LIST, level 1: HDA delegation trust (RFC 9886 sec 6).
    r.raa_trusted = trust.trusted_raa_for(det_bytes)
    r.hda_trusted = trust.trusted_hda_for(det_bytes)

    if not r.nests:
        # Does not fall under any trusted RAA /44 + HDA /56.
        r.findings.append(("E-ZONE-01",
                           f"DET does not nest under any trusted RAA/HDA zone "
                           f"(claims RAA={r.fields['raa']} HDA={r.fields['hda']}, "
                           f"HDA zone {r.hda_zone})"))

    # (b) ALLOW-LIST, level 2: explicit per-UA enrolment.
    entry, level = trust.entry_for_det(det_bytes)
    if entry is not None and level == "UA":
        r.ua_enrolled = entry
    # An anchor entity (APEX/RAA/HDA) resolved by its own DET is legitimately
    # "on the list" too, but it is not a UA enrolment; the printer names it.
    elif entry is not None:
        r.ua_enrolled = None  # keep UA level strict

    if not r.on_allow_list and entry is None:
        r.findings.append(("E-TRUST-01",
                           "DET is not in the trusted-identities file at any "
                           "level (no trusted HDA delegation, not individually "
                           "enrolled)"))

    # (c) CRYPTOGRAPHIC — only if a key for THIS exact DET is on file.
    key = trust.key_for_det(det_bytes)
    if key is None:
        r.binding = "NOT_CHECKED"
        r.findings.append(("E-KEY-01",
                           "no public key registered for this DET — DET<->key "
                           "binding NOT checked"))
    elif not HAVE_DET:
        r.binding = "NOT_CHECKED"
        r.findings.append(("E-KEY-01",
                           "a key is on file but det.py is unavailable, so the "
                           "cSHAKE128 binding could not be computed"))
    else:
        r.registered_key = key
        if det.verify_det_binding(det_bytes, key):
            r.binding = "VERIFIED"
        else:
            r.binding = "MISMATCH"
            r.findings.append(("E-DET-02",
                               "registered key does NOT derive this DET "
                               "(cSHAKE128 binding mismatch, RFC 9374 3.5.2)"))
    return r


# ---------------------------------------------------------------------------
#  Single source of truth for the observer's keyring.
#
#  Every DET->public_key the observer knows comes from the trusted-identities
#  file (this function), NOT from a hard-coded table. This replaces the old
#  observer.BUILTIN_KEYS so keys live in exactly one place (hierarchy.json).
# ---------------------------------------------------------------------------
def iter_known_keys(trust):
    """Yield (det_hex, pubkey_hex, label) for every entity in the trust store
    that has a public key: UAs, and the apex/raa/hda authorities. Used to build
    the observer keyring and by check_hierarchy.py."""
    seen = set()
    def emit(entry, kind):
        d = entry.get("_det_bytes")
        p = entry.get("_pub_bytes")
        if d is None or p is None:
            return
        h = bytes(d).hex().upper()
        if h in seen:
            return
        seen.add(h)
        role = entry.get("_role", kind)
        return (h, bytes(p).hex().upper(), role)
    out = []
    for e in trust.uas:
        r = emit(e, "UA");   out.append(r) if r else None
    for e in trust.hdas:
        r = emit(e, "HDA");  out.append(r) if r else None
    for e in trust.raas:
        r = emit(e, "RAA");  out.append(r) if r else None
    if trust.apex:
        r = emit(trust.apex, "APEX")
        if r: out.append(r)
    return [x for x in out if x]
